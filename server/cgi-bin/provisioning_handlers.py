"""RemotePower — provisioning blueprints + health-gated rollouts + terraform exec.

Bound-module decomposition of api.py (same pattern as tickets_handlers.py —
see its module docstring for the full rationale): every api service, and
every call BETWEEN these functions, resolves dynamically through the bound
``A`` namespace proxy so test monkeypatching of api attributes keeps
working; api.py execs a PRIVATE instance per api instance and binds its own
globals(); handler names are bound back into api's globals so the route
tables and all existing callers are untouched. Constants and routes stay in
api.py. Adding a feature here: edit this file; new routes go in api.py's
_PATTERN_ROUTE_DEFS / _build_exact_routes as usual.
"""
import json
import os
import re
import secrets
import sys
import time


class _ApiNamespace:
    __slots__ = ('_g',)

    def __init__(self, g):
        self._g = g

    def __getattr__(self, name):
        try:
            return self._g[name]
        except KeyError:
            raise AttributeError(f'api namespace has no {name!r}') from None


A = None


def bind(api_globals):
    """Called once per api instance, with api's ``globals()``."""
    global A
    A = _ApiNamespace(api_globals)


def _blueprints_load():
    data = A.load(A.PROVISION_FILE)
    if not isinstance(data, dict) or 'blueprints' not in data:
        return {'blueprints': []}
    return data


def _provisioning_enabled():
    return bool((A.load(A.CONFIG_FILE) or {}).get('show_provisioning'))


def _rollout_advance(roll, devices, cmds, pending=None):
    """Advance a single running rollout by at most one transition. Returns True
    if devices/cmds were mutated (a ring was dispatched). `pending` (a list)
    collects ('event', payload) tuples to fire AFTER the ROLLOUTS_FILE lock —
    fire_webhook takes its own lock, so it must never run inside this one."""
    if pending is None:
        pending = []
    if roll.get('state') != 'running':
        return False
    idx = roll.get('current_ring', 0)
    rings = roll.get('rings') or []
    rs = roll.get('rings_state') or []
    if idx >= len(rings) or idx >= len(rs):
        roll['state'] = 'done'; return False
    rstate = rs[idx]
    now = int(time.time())
    mutated = False
    if rstate.get('state') == 'pending':
        dispatched, queued = A._rollout_dispatch_ring(roll, idx, devices, cmds)
        rstate['dispatched_ids'] = dispatched
        rstate['dispatched_at'] = now
        rstate['total'] = len(dispatched)
        rstate['queued'] = queued
        rstate['state'] = 'verifying' if dispatched else 'done'
        A._rollout_log(roll, f'ring {idx+1}/{len(rings)} "{rings[idx].get("name")}" '
                           f'dispatched to {len(dispatched)} device(s)')
        if not dispatched:
            rstate['done_at'] = now
        mutated = True
    if rstate.get('state') == 'verifying':
        ok, failed, total = A._rollout_ring_progress(roll, rstate, devices, cmds)
        rstate['ok_count'] = ok
        rstate['failed_count'] = failed
        elapsed_min = (now - (rstate.get('dispatched_at') or now)) / 60.0
        verify_min = roll.get('verify_minutes', A._ROLLOUT_VERIFY_MIN_DEFAULT)
        # v4.10.0: health gate — auto-halt if a dispatched host's health drops
        # below the floor during the watch window. Baseline captured at dispatch
        # so a pre-existing low score never false-trips; only a DROP halts.
        hg = roll.get('health_gate') or {}
        if hg.get('enabled'):
            try:
                floor = int(hg.get('threshold', 70))
                hb = {d['device_id']: d['score'] for d in (A._fleet_health().get('devices') or [])}
                if not rstate.get('baseline_health'):
                    rstate['baseline_health'] = {did: hb.get(did, 100)
                                                 for did in (rstate.get('dispatched_ids') or [])}
                base = rstate['baseline_health']
                degraded = [did for did in (rstate.get('dispatched_ids') or [])
                            if hb.get(did, 100) < floor and base.get(did, 100) >= floor]
                if degraded:
                    rstate['state'] = 'failed'
                    rstate['health_failures'] = degraded
                    roll['state'] = 'failed'
                    names = ', '.join(devices.get(d, {}).get('name', d) for d in degraded[:3])
                    A._rollout_log(roll, f'ring {idx+1} HALTED — health dropped below {floor} '
                                       f'on {len(degraded)} host(s) ({names}); rollout paused')
                    pending.append(('rollout_halted', {
                        'rollout_id': roll.get('id'), 'name': roll.get('name'),
                        'ring': idx + 1, 'reason': 'health_gate', 'threshold': floor,
                        'degraded': len(degraded),
                    }))
            except Exception:
                pass
        if rstate.get('state') == 'verifying' and (ok >= total or elapsed_min >= verify_min):
            if total > 0 and ok == 0:
                rstate['state'] = 'failed'
                roll['state'] = 'failed'
                A._rollout_log(roll, f'ring {idx+1} FAILED — 0/{total} verified after '
                                   f'{int(elapsed_min)}m; rollout halted')
                pending.append(('rollout_halted', {
                    'rollout_id': roll.get('id'), 'name': roll.get('name'),
                    'ring': idx + 1, 'reason': 'no_verification',
                }))
            else:
                rstate['state'] = 'done'
                rstate['done_at'] = now
                A._rollout_log(roll, f'ring {idx+1} done — {ok}/{total} verified'
                                   + (f', {failed} stalled' if failed else ''))
                if idx + 1 >= len(rings):
                    roll['state'] = 'done'
                    A._rollout_log(roll, 'rollout complete')
                elif roll.get('auto_promote'):
                    roll['current_ring'] = idx + 1
                    A._rollout_log(roll, f'auto-promoting to ring {idx+2}')
                else:
                    roll['state'] = 'paused'
                    A._rollout_log(roll, f'ring {idx+1} done — awaiting manual promote')
    return mutated


def _rollout_dispatch_ring(roll, idx, devices, cmds):
    """Queue the rollout action onto ring `idx`'s devices. Mutates devices+cmds
    in place (caller saves). Skips quarantined devices. Returns (dispatched_ids,
    queued_command_string)."""
    ring = roll['rings'][idx]
    ids = A._rollout_resolve_ring(ring.get('selector'), devices)
    now = int(time.time())
    if roll.get('action') == 'upgrade':
        # v5.8.0 (B1.3 patch rings): a reboot-flagged rollout uses the
        # upgrade+reboot command so each ring reboots as it patches (health-gated
        # per ring). Default = bare upgrade, no reboot (unchanged).
        queued = (f'exec:{A._SCHED_UPGRADE_REBOOT_CMD}' if roll.get('reboot')
                  else f'exec:{A._UPGRADE_CMD}')
    elif roll.get('action') == 'self-update':
        queued = 'update'   # the agent's own hash-verified self-update command
    else:
        queued = f'exec:{roll.get("_script_body", "")}'
    dispatched = []
    actor = roll.get('created_by', 'system')
    for dev_id in ids:
        dev = devices.get(dev_id)
        if not dev or A._device_quarantined(dev):
            continue
        cmds.setdefault(dev_id, [])
        if queued not in cmds[dev_id]:
            cmds[dev_id].append(queued)
        if roll.get('action') == 'upgrade':
            dev['upgrade_queued_at'] = now
            dev['upgrade_pending_before'] = ((dev.get('sysinfo') or {}).get('packages') or {}).get('upgradable')
            dev['force_package_scan'] = True
        dispatched.append(dev_id)
        A.log_command(actor, dev_id, dev.get('name', dev_id),
                    f'rollout "{roll.get("name","")[:30]}" ring {ring.get("name","")[:20]}')
    return dispatched, queued


def _rollout_log(roll, msg):
    h = roll.setdefault('history', [])
    h.append({'ts': int(time.time()), 'msg': str(msg)[:200]})
    roll['history'] = h[-100:]
    roll['updated_at'] = int(time.time())


def _rollout_public(roll):
    """Strip internal (underscore-prefixed) keys for the API."""
    return {k: v for k, v in roll.items() if not k.startswith('_')}


def _rollout_resolve_ring(selector, devices):
    """Resolve a ring selector ({'type':'group'|'tag'|'ids', 'value'/'ids'}) to a
    de-duped list of valid device ids that currently exist."""
    t = (selector or {}).get('type')
    out = []
    if t == 'ids':
        for d in (selector.get('ids') or [])[:500]:
            d = str(d).strip()
            if A._validate_id(d) and d in devices:
                out.append(d)
    elif t == 'group':
        g = str(selector.get('value') or '')
        out = [did for did, dev in devices.items()
               if isinstance(dev, dict) and (dev.get('group') or '') == g]
    elif t == 'tag':
        tag = str(selector.get('value') or '')
        out = [did for did, dev in devices.items()
               if isinstance(dev, dict) and tag in (dev.get('tags') or [])]
    seen, uniq = set(), []
    for d in out:
        if d not in seen:
            seen.add(d); uniq.append(d)
    return uniq


def _rollout_ring_progress(roll, rstate, devices, cmds):
    """(ok, failed, total) for a dispatched ring. For upgrades, ok == verified
    'ok' and failed == 'stalled' (real post-deploy verification). For scripts we
    can only confirm delivery, so ok == command consumed from the queue."""
    ids = rstate.get('dispatched_ids') or []
    total = len(ids)
    now = int(time.time())
    ok = failed = 0
    if roll.get('action') == 'upgrade':
        for dev_id in ids:
            st = A._upgrade_verify_status(devices.get(dev_id) or {}, now)
            if st == 'ok':
                ok += 1
            elif st == 'stalled':
                failed += 1
    else:
        q = rstate.get('queued')
        for dev_id in ids:
            if q and q not in (cmds.get(dev_id) or []):
                ok += 1
    return ok, failed, total


def _rollout_script_body(script_id):
    """Body of a saved script by id, or '' if not found."""
    for s in (A.load(A.SCRIPTS_FILE) or {}).get('scripts', []):
        if s.get('id') == script_id:
            return s.get('body', '')
    return ''


def _rollout_tick():
    """Advance every running rollout. Cheap early-out when none are running."""
    try:
        rolls = (A.load(A.ROLLOUTS_FILE) or {}).get('rollouts') or []
    except Exception:
        return
    if not any(r.get('state') == 'running' for r in rolls):
        return
    pending = []   # v4.10.0: ('event', payload) tuples fired AFTER the lock
    try:
        with A._LockedUpdate(A.ROLLOUTS_FILE) as store:
            rolls = store.get('rollouts') or []
            if not any(r.get('state') == 'running' for r in rolls):
                return
            devices = A.load(A.DEVICES_FILE)
            cmds = A.load(A.CMDS_FILE)
            dirty = False
            for roll in rolls:
                if roll.get('state') != 'running':
                    continue
                if roll.get('action') == 'script' and roll.get('script_id'):
                    roll['_script_body'] = A._rollout_script_body(roll['script_id'])
                if A._rollout_advance(roll, devices, cmds, pending):
                    dirty = True
                roll.pop('_script_body', None)
            if dirty:
                # issue #8: this is the ONE permitted bare DEVICES write — it runs
                # while holding _LockedUpdate(ROLLOUTS_FILE), so it can't take a
                # second _LockedUpdate(DEVICES_FILE) (nested BEGIN IMMEDIATE would
                # throw under SQLite). Cross-lock atomicity here is a known residual;
                # the guardrail test allowlists _rollout_tick.
                A.save(A.DEVICES_FILE, devices)
                A.save(A.CMDS_FILE, cmds)
            store['rollouts'] = rolls
    except Exception as e:
        sys.stderr.write(f'[remotepower] rollout tick failed: {e}\n')
    for _ev, _pl in pending:   # outside the ROLLOUTS_FILE lock — fire-safe
        try:
            A.fire_webhook(_ev, _pl)
        except Exception:
            pass


def _rollout_tick_if_due():
    now = time.time()
    if now - A._last_rollout_tick[0] < A._ROLLOUT_TICK_INTERVAL:
        return
    A._last_rollout_tick[0] = now
    A._rollout_tick()


def _terraform_available():
    import shutil
    return shutil.which('terraform') is not None


def _terraform_run(bp, op, supplied):
    """Run `terraform <op>` for a blueprint in its persistent workdir. Returns
    (output, returncode). Pure subprocess orchestration — no request access."""
    import subprocess
    workdir = A.IAC_RUNS_DIR / re.sub(r'[^A-Za-z0-9_-]', '_', str(bp['id']))[:64]
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(workdir, 0o700)   # may hold provider plugins + state
    except OSError:
        pass
    (workdir / 'main.tf').write_text(bp.get('content', ''))
    # declared variables: non-secret → on-disk tfvars; secret → env only.
    tfvars, env = {}, dict(os.environ)
    for v in bp.get('variables', []):
        if not isinstance(v, dict) or not v.get('name'):
            continue
        name = v['name']
        val = supplied.get(name, v.get('default', ''))
        val = '' if val is None else str(val)
        if v.get('secret'):
            env['TF_VAR_' + name] = val
            # Bare env too, for cloud-provider creds (AWS_ACCESS_KEY_ID …). Guard
            # against a variable name that would clobber a critical process env
            # var (PATH/HOME/LD_*/…) and break or subvert the terraform
            # subprocess — TF_VAR_<name> still carries the value regardless.
            if name.upper() not in A._TF_ENV_PROTECTED and \
               not name.upper().startswith(('LD_', 'DYLD_')):
                env[name] = val
        else:
            tfvars[name] = val
    (workdir / 'rp.auto.tfvars.json').write_text(json.dumps(tfvars))
    env['TF_IN_AUTOMATION'] = '1'
    env['TF_INPUT'] = '0'
    parts, rc = [], 0

    def _tf(args, timeout):
        try:
            p = subprocess.run(['terraform', *args], capture_output=True, text=True,  # nosec B603 B607
                               timeout=timeout, cwd=str(workdir), env=env)
            parts.append((p.stdout or '') + (('\n' + p.stderr) if p.stderr else ''))
            return p.returncode
        except subprocess.TimeoutExpired:
            parts.append(f'\n[terraform {args[0]}] timed out')
            return 124
        except FileNotFoundError:
            parts.append('terraform not found')
            return 127

    if not (workdir / '.terraform').exists():
        rc = _tf(['init', '-input=false', '-no-color'], 300)
    if rc == 0:
        if op == 'plan':
            rc = _tf(['plan', '-input=false', '-no-color'], 900)
        elif op == 'apply':
            rc = _tf(['apply', '-input=false', '-auto-approve', '-no-color'], 1800)
        elif op == 'destroy':
            rc = _tf(['destroy', '-input=false', '-auto-approve', '-no-color'], 1800)
    return '\n'.join(parts)[-65536:], rc


def handle_blueprint_create():
    """POST /api/provisioning/blueprints — store a blueprint (admin)."""
    actor = A.require_admin_auth()
    if not A._provisioning_enabled():
        A.respond(403, {'error': 'Provisioning is disabled'})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    name = A._sanitize_str(body.get('name', ''), 120).strip()
    kind = str(body.get('kind', '')).strip()
    content = body.get('content', '')
    if not name or kind not in A._BLUEPRINT_KINDS or not isinstance(content, str) or not content.strip():
        A.respond(400, {'error': 'name, a valid kind, and content are required'})
    if len(content.encode('utf-8')) > A.MAX_BLUEPRINT_BYTES:
        A.respond(400, {'error': f'blueprint too large (max {A.MAX_BLUEPRINT_BYTES} bytes)'})
    data = A._blueprints_load()
    if len(data['blueprints']) >= A.MAX_BLUEPRINTS:
        A.respond(400, {'error': f'blueprint limit reached (max {A.MAX_BLUEPRINTS})'})
    bp = {'id': secrets.token_urlsafe(8), 'name': name, 'kind': kind,
          'folder': A._bp_clean_folder(body.get('folder', '')),
          'content': content, 'variables': A._bp_clean_vars(body.get('variables')),
          'created': int(time.time()), 'updated': int(time.time()),
          'created_by': actor}
    data['blueprints'].append(bp)
    A.save(A.PROVISION_FILE, data)
    A.audit_log(actor, 'blueprint_create', detail=f'blueprint={bp["id"]} name={name} kind={kind}')
    A.respond(200, {'ok': True, 'id': bp['id']})


def handle_blueprint_delete(bp_id):
    """DELETE /api/provisioning/blueprints/{id} (admin)."""
    actor = A.require_admin_auth()
    if not A._provisioning_enabled():
        A.respond(403, {'error': 'Provisioning is disabled'})
    if A.method() != 'DELETE':
        A.respond(405, {'error': 'Method not allowed'})
    data = A._blueprints_load()
    if not any(b['id'] == bp_id for b in data['blueprints']):
        A.respond(404, {'error': 'blueprint not found'})
    # v5.6.0: don't orphan live infrastructure — a terraform blueprint with
    # resources in its state must be destroyed (Run → Destroy) before deletion.
    safe_id = re.sub(r'[^A-Za-z0-9_-]', '_', str(bp_id))[:64]
    wd = A.IAC_RUNS_DIR / safe_id
    state = wd / 'terraform.tfstate'
    if state.exists():
        try:
            if (json.loads(state.read_text()) or {}).get('resources'):
                A.respond(409, {'error': 'This blueprint has live Terraform state — '
                                       'Run → Destroy first, then delete.'})
        except (ValueError, OSError):
            pass
    # Remove under the store lock (concurrent status writes from another
    # blueprint's run must not be clobbered — see handle_blueprint_run).
    with A._LockedUpdate(A.PROVISION_FILE) as d:
        if isinstance(d, dict):
            d['blueprints'] = [b for b in d.get('blueprints', [])
                               if not (isinstance(b, dict) and b.get('id') == bp_id)]
    # clean up the (now state-free) workdir + lockfile
    import shutil
    shutil.rmtree(wd, ignore_errors=True)
    try:
        (A.IAC_RUNS_DIR / (safe_id + '.lock')).unlink()
    except OSError:
        pass
    A.audit_log(actor, 'blueprint_delete', detail=f'blueprint={bp_id}')
    A.respond(200, {'ok': True})


def handle_blueprint_render(bp_id):
    """POST /api/provisioning/blueprints/{id}/render — substitute ${var}
    placeholders with the supplied values (plus ${rp_*} macros) and return the
    rendered text. Pure string substitution: no eval, no shell, no execution."""
    A.require_admin_auth()
    if not A._provisioning_enabled():
        A.respond(403, {'error': 'Provisioning is disabled'})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    bp = next((b for b in A._blueprints_load()['blueprints'] if b['id'] == bp_id), None)
    if not bp:
        A.respond(404, {'error': 'blueprint not found'})
    fname = re.sub(r'[^A-Za-z0-9._-]', '_', bp.get('name', 'blueprint')) or 'blueprint'
    # Terraform owns ${...} for its own HCL interpolation — never rewrite it.
    # Terraform blueprints take their values natively as var.<name> at Run time;
    # Render just returns the HCL verbatim so it copies cleanly.
    if bp.get('kind') == 'terraform':
        A.respond(200, {'ok': True, 'rendered': bp.get('content', ''),
                      'missing': [], 'filename': fname})
    supplied = body.get('vars') if isinstance(body.get('vars'), dict) else {}
    base = A._request_base_url(os.environ)
    # Convenience macros, always available to every blueprint.
    macros = {
        'rp_server_url': base,
        'rp_agent_install': f'curl -fsSL {base}/install | sudo sh -s -- --token <enrollment-token>',
    }
    values = dict(macros)
    for v in bp.get('variables', []):
        if isinstance(v, dict) and v.get('name'):
            values[v['name']] = str(v.get('default', ''))
    for k, val in supplied.items():
        if isinstance(k, str) and A._BLUEPRINT_VAR_RE.fullmatch('${' + k + '}'):
            values[k] = '' if val is None else str(val)[:8192]
    missing = []

    def _sub(mo):
        key = mo.group(1)
        if key in values:
            return values[key]
        missing.append(key)
        return mo.group(0)

    rendered = A._BLUEPRINT_VAR_RE.sub(_sub, bp.get('content', ''))
    A.respond(200, {'ok': True, 'rendered': rendered,
                  'missing': sorted(set(missing)), 'filename': fname})


def handle_blueprint_run(bp_id):
    """POST /api/provisioning/blueprints/{id}/run — execute a TERRAFORM blueprint
    server-side. Body: {op: plan|apply|destroy, vars:{...}}. Admin-only; gated by
    BOTH the provisioning toggle and iac_execute_enabled."""
    actor = A.require_admin_auth()
    if not A._provisioning_enabled():
        A.respond(403, {'error': 'Provisioning is disabled'})
    if not A._iac_execute_enabled():
        A.respond(403, {'error': 'Server-side execution is disabled — enable it under Settings → Advanced'})
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    if not A._terraform_available():
        A.respond(400, {'error': 'terraform is not installed on the server'})
    body = A.get_json_obj()
    op = str(body.get('op', '')).strip()
    if op not in ('plan', 'apply', 'destroy'):
        A.respond(400, {'error': 'op must be plan, apply or destroy'})
    bp = next((b for b in A._blueprints_load()['blueprints'] if b['id'] == bp_id), None)
    if not bp:
        A.respond(404, {'error': 'blueprint not found'})
    if bp.get('kind') != 'terraform':
        A.respond(400, {'error': 'only terraform blueprints can be executed; the others are render-only'})
    supplied = body.get('vars') if isinstance(body.get('vars'), dict) else {}
    # Per-blueprint exclusive lock: terraform's own state lock guards apply, but
    # serialise here too so two ops on one blueprint can't race init/plan.
    import fcntl
    A.IAC_RUNS_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = A.IAC_RUNS_DIR / (re.sub(r'[^A-Za-z0-9_-]', '_', str(bp_id))[:64] + '.lock')
    lf = open(lock_path, 'w')   # noqa: SIM115
    try:
        try:
            fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            A.respond(409, {'error': 'a run is already in progress for this blueprint'})
        out, rc = A._terraform_run(bp, op, supplied)
    finally:
        try:
            fcntl.flock(lf, fcntl.LOCK_UN)
            lf.close()
        except Exception:
            pass
    # Status write under the store lock — two runs on DIFFERENT blueprints each
    # hold only their own per-blueprint flock, so a bare load/mutate/save here
    # could lose the other's status badge. (audit_log is self-locking → after.)
    with A._LockedUpdate(A.PROVISION_FILE) as data:
        if isinstance(data, dict):
            for b in data.setdefault('blueprints', []):
                if isinstance(b, dict) and b.get('id') == bp_id:
                    b['last_op'] = op
                    b['last_run'] = int(time.time())
                    b['last_rc'] = rc
                    break
    A.audit_log(actor, 'blueprint_run', detail=f'blueprint={bp_id} op={op} rc={rc}')
    A.respond(200, {'ok': rc == 0, 'op': op, 'rc': rc, 'output': out})


def handle_blueprint_update(bp_id):
    """PUT /api/provisioning/blueprints/{id} (admin)."""
    actor = A.require_admin_auth()
    if not A._provisioning_enabled():
        A.respond(403, {'error': 'Provisioning is disabled'})
    if A.method() != 'PUT':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    data = A._blueprints_load()
    bp = next((b for b in data['blueprints'] if b['id'] == bp_id), None)
    if not bp:
        A.respond(404, {'error': 'blueprint not found'})
    if 'name' in body:
        bp['name'] = A._sanitize_str(body['name'], 120).strip() or bp['name']
    if 'folder' in body:
        bp['folder'] = A._bp_clean_folder(body['folder'])
    if 'kind' in body and body['kind'] in A._BLUEPRINT_KINDS:
        bp['kind'] = body['kind']
    if 'content' in body:
        c = body['content']
        if not isinstance(c, str) or not c.strip():
            A.respond(400, {'error': 'content must be non-empty'})
        if len(c.encode('utf-8')) > A.MAX_BLUEPRINT_BYTES:
            A.respond(400, {'error': 'blueprint too large'})
        bp['content'] = c
    if 'variables' in body:
        bp['variables'] = A._bp_clean_vars(body['variables'])
    bp['updated'] = int(time.time())
    A.save(A.PROVISION_FILE, data)
    A.audit_log(actor, 'blueprint_update', detail=f'blueprint={bp_id}')
    A.respond(200, {'ok': True})


def handle_blueprints_list():
    """GET /api/provisioning/blueprints — all blueprints (admin)."""
    A.require_admin_auth()
    if not A._provisioning_enabled():
        A.respond(200, {'ok': True, 'enabled': False, 'blueprints': [],
                      'kinds': list(A._BLUEPRINT_KINDS)})
    bps = [A._bp_public(b) for b in A._blueprints_load()['blueprints']]
    A.respond(200, {'ok': True, 'enabled': True, 'blueprints': bps,
                  'kinds': list(A._BLUEPRINT_KINDS),
                  # v5.6.0: tells the UI whether terraform blueprints can be RUN
                  'execute_enabled': A._iac_execute_enabled(),
                  'terraform_available': A._terraform_available()})


def handle_rollout_action(roll_id, action):
    """POST /api/rollouts/<id>/<start|pause|resume|cancel|promote>."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    err_box = [None, None]   # [error, new_rollback_id]  (v5.0.0 #F5)
    with A._LockedUpdate(A.ROLLOUTS_FILE) as store:
        rolls = store.get('rollouts') or []
        roll = next((r for r in rolls if r.get('id') == roll_id), None)
        if not roll:
            A.respond(404, {'error': 'rollout not found'})
        st = roll.get('state')
        if action == 'start':
            if st not in ('draft', 'paused'):
                err_box[0] = f'cannot start from state {st}'
            else:
                roll['state'] = 'running'
                A._rollout_log(roll, 'started' if st == 'draft' else 'resumed')
        elif action == 'pause':
            if st != 'running':
                err_box[0] = 'only a running rollout can be paused'
            else:
                roll['state'] = 'paused'; A._rollout_log(roll, 'paused')
        elif action == 'resume':
            if st != 'paused':
                err_box[0] = 'only a paused rollout can be resumed'
            else:
                roll['state'] = 'running'; A._rollout_log(roll, 'resumed')
        elif action == 'cancel':
            if st in ('done', 'cancelled'):
                err_box[0] = f'already {st}'
            else:
                roll['state'] = 'cancelled'; A._rollout_log(roll, 'cancelled')
        elif action == 'promote':
            idx = roll.get('current_ring', 0)
            rs = roll.get('rings_state') or []
            if st not in ('running', 'paused'):
                err_box[0] = f'cannot promote from {st}'
            elif idx >= len(rs) or rs[idx].get('state') != 'done':
                err_box[0] = 'current ring is not done yet'
            elif idx + 1 >= len(roll.get('rings') or []):
                err_box[0] = 'no further ring to promote to'
            else:
                roll['current_ring'] = idx + 1
                roll['state'] = 'running'
                A._rollout_log(roll, f'manually promoted to ring {idx+2}')
        elif action == 'rollback':
            # v5.0.0 (#F5): create + start a NEW script rollout that runs the
            # configured rollback script on exactly the devices this rollout
            # already reached (the union of every ring's dispatched_ids).
            if roll.get('action') != 'script' or not roll.get('rollback_script_id'):
                err_box[0] = ('rollback needs a script rollout with a rollback '
                              'script configured (agent-binary rollback requires a '
                              'reinstall)')
            else:
                hit = []
                for rs in (roll.get('rings_state') or []):
                    for d in (rs.get('dispatched_ids') or []):
                        if d not in hit:
                            hit.append(d)
                if not hit:
                    err_box[0] = 'this rollout has not dispatched to any device yet'
                else:
                    rb = {
                        'id': secrets.token_hex(8),
                        'name': f'Rollback of {roll.get("name", roll_id)}'[:80],
                        'action': 'script',
                        'script_id': roll['rollback_script_id'],
                        'rollback_script_id': '',
                        'rings': [{'name': 'rollback', 'selector': {'type': 'ids', 'ids': hit}}],
                        'rings_state': [{'state': 'pending', 'dispatched_ids': [], 'total': 0,
                                         'ok_count': 0, 'failed_count': 0}],
                        'auto_promote': True,
                        'verify_minutes': roll.get('verify_minutes', A._ROLLOUT_VERIFY_MIN_DEFAULT),
                        'health_gate': {'enabled': False, 'threshold': 70},
                        'state': 'running',
                        'current_ring': 0,
                        'history': [],
                        'rolled_back_from': roll_id,
                        'created_by': actor,
                        'created_at': int(time.time()),
                        'updated_at': int(time.time()),
                    }
                    A._rollout_log(rb, f'rollback of {roll_id} — {len(hit)} device(s)')
                    rolls.append(rb)
                    roll['rolled_back_by'] = rb['id']
                    A._rollout_log(roll, f'rolled back via {rb["id"]}')
                    err_box[1] = rb['id']  # carry the new id out for the response
        else:
            err_box[0] = 'unknown action'
        store['rollouts'] = rolls
    if err_box[0]:
        A.respond(400, {'error': err_box[0]})
    A.audit_log(actor, f'rollout_{action}', f'id={roll_id}')
    A._rollout_tick()   # dispatch/advance immediately so the UI reflects it
    rolls = (A.load(A.ROLLOUTS_FILE) or {}).get('rollouts') or []
    fresh = next((r for r in rolls if r.get('id') == roll_id), None)
    A.respond(200, {'ok': True, 'rollout': A._rollout_public(fresh) if fresh else None,
                  'rollback_id': err_box[1]})


def handle_rollout_delete(roll_id):
    """DELETE /api/rollouts/<id>."""
    actor = A.require_admin_auth()
    with A._LockedUpdate(A.ROLLOUTS_FILE) as store:
        rolls = store.get('rollouts') or []
        remaining = [r for r in rolls if r.get('id') != roll_id]
        if len(remaining) == len(rolls):
            A.respond(404, {'error': 'rollout not found'})
        store['rollouts'] = remaining
    A.audit_log(actor, 'rollout_delete', f'id={roll_id}')
    A.respond(200, {'ok': True})


def handle_rollouts_create():
    """POST /api/rollouts — create a draft rollout."""
    actor = A.require_admin_auth()
    if A.method() != 'POST':
        A.respond(405, {'error': 'Method not allowed'})
    body = A.get_json_obj()
    name = A._sanitize_str(body.get('name', ''), 80)
    if not name:
        A.respond(400, {'error': 'name required'})
    action = body.get('action') or 'upgrade'
    if action not in ('upgrade', 'script', 'self-update'):
        A.respond(400, {'error': 'action must be upgrade, script or self-update'})
    script_id = ''
    rollback_script_id = ''
    if action == 'script':
        script_id = A._sanitize_str(body.get('script_id', ''), 64)
        if not A._rollout_script_body(script_id):
            A.respond(400, {'error': 'script_id not found'})
        # v5.0.0 (#F5): optional rollback script — a one-click "undo" that
        # re-dispatches this script to exactly the devices the rollout reached.
        rollback_script_id = A._sanitize_str(body.get('rollback_script_id', ''), 64)
        if rollback_script_id and not A._rollout_script_body(rollback_script_id):
            A.respond(400, {'error': 'rollback_script_id not found'})
    raw_rings = body.get('rings') if isinstance(body.get('rings'), list) else []
    rings = []
    for r in raw_rings[:10]:
        if not isinstance(r, dict):
            continue
        sel = r.get('selector') or {}
        st = sel.get('type')
        if st not in ('group', 'tag', 'ids'):
            continue
        clean = {'type': st}
        if st == 'ids':
            clean['ids'] = [str(x).strip() for x in (sel.get('ids') or [])[:500]
                            if A._validate_id(str(x).strip())]
            if not clean['ids']:
                continue
        else:
            clean['value'] = A._sanitize_str(sel.get('value', ''), 128)
            if not clean['value']:
                continue
        rings.append({'name': A._sanitize_str(r.get('name', ''), 40) or f'ring {len(rings)+1}',
                      'selector': clean})
    if not rings:
        A.respond(400, {'error': 'at least one ring with a valid selector required'})
    try:
        vmin = max(1, min(A._ROLLOUT_VERIFY_MIN_MAX,
                          int(body.get('verify_minutes') or A._ROLLOUT_VERIFY_MIN_DEFAULT)))
    except (TypeError, ValueError):
        vmin = A._ROLLOUT_VERIFY_MIN_DEFAULT
    # v4.10.0: optional health gate — auto-halt the rollout if a dispatched host's
    # health score drops below the floor during the verify window. Default OFF.
    _hg_in = body.get('health_gate') or {}
    try:
        _hg_floor = max(1, min(100, int(_hg_in.get('threshold', 70))))
    except (TypeError, ValueError):
        _hg_floor = 70
    health_gate = {'enabled': bool(_hg_in.get('enabled')), 'threshold': _hg_floor}
    roll = {
        'id': secrets.token_hex(8),
        'name': name,
        'action': action,
        'script_id': script_id,
        'rollback_script_id': rollback_script_id,
        'rings': rings,
        'rings_state': [{'state': 'pending', 'dispatched_ids': [], 'total': 0,
                         'ok_count': 0, 'failed_count': 0} for _ in rings],
        'auto_promote': bool(body.get('auto_promote')),
        'verify_minutes': vmin,
        'health_gate': health_gate,
        'state': 'draft',
        'current_ring': 0,
        'history': [],
        'created_by': actor,
        'created_at': int(time.time()),
        'updated_at': int(time.time()),
    }
    A._rollout_log(roll, f'created — {action}, {len(rings)} ring(s), '
                       f'{"auto" if roll["auto_promote"] else "manual"} promote')
    with A._LockedUpdate(A.ROLLOUTS_FILE) as store:
        rl = store.setdefault('rollouts', [])
        if len(rl) >= 100:
            A.respond(400, {'error': 'too many rollouts (max 100) — delete old ones'})
        rl.append(roll)
    A.audit_log(actor, 'rollout_create', f'id={roll["id"]} action={action} rings={len(rings)}')
    A.respond(200, {'ok': True, 'rollout': A._rollout_public(roll)})


def handle_rollouts_list():
    """GET /api/rollouts — list rollouts, advancing running ones first."""
    A.require_auth()
    A._rollout_tick()
    rolls = (A.load(A.ROLLOUTS_FILE) or {}).get('rollouts') or []
    rolls = sorted(rolls, key=lambda r: -(r.get('created_at') or 0))
    A.respond(200, {'rollouts': [A._rollout_public(r) for r in rolls]})
