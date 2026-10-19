"""
四个脚本的执行账号 / quota 项目参数（2026-10-18）：--gcloud-account、--quota-project 都是可选的，
不给时由 gcp_auth.resolve_auth 自动确定；确定不了时 [ERROR]（附 gcloud auth login / gcloud config set project 提示）、退出码 2、不做任何变更。
apply_bypass_rls.py / apply_copilot_rls.py 原来的 --project 统一改名为 --quota-project。
"""

import pytest

import apply_bypass_rls
import apply_copilot_rls
import gcp_auth
import list_principals
import rollback_rls
from tests.unit.fakes import REG, FakeWorld, fake_auth, install

T1 = "p.dw.t1"
COND, MAP = "p.auth.cond", "p.auth.map"
SA = "cop@p.iam.gserviceaccount.com"


@pytest.fixture
def world(monkeypatch):
    w = FakeWorld()
    w.add_table(T1, schema={"region": ("STRING", "NULLABLE")})
    w.add_table(COND, rls_enabled=0)
    w.add_table(MAP, rls_enabled=0)
    w.condition_fields[COND] = [("id", "STRING", "NULLABLE"), ("sa", "STRING", "NULLABLE"), ("region", "STRING", "REPEATED")]
    w.condition_sas[COND] = [SA]
    w.mapping_rows[MAP] = [{"table_name": T1, "col_name": "region", "to_name": "region"}]
    w.project_sas["p"] = [SA]
    install(monkeypatch, w)
    calls = []

    def recording_auth(gcloud_account=None, quota_project=None):
        calls.append((gcloud_account, quota_project))
        return fake_auth(gcloud_account, quota_project)
    for mod in (list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls):
        monkeypatch.setattr(mod, "resolve_auth", recording_auth)
    w.auth_calls = calls
    return w


def invocations(tmp_path):
    return {
        list_principals: ["--projects", "p", "-o", str(tmp_path / "p.csv")],
        apply_bypass_rls: ["--group", "g@x.com", "--tables", T1, "--registry-table", REG],
        apply_copilot_rls: ["--condition-table", COND, "--mapping-table", MAP, "--registry-table", REG,
                            "--group", "group_copilot@x.com", "-o", str(tmp_path / "c.csv")],
        rollback_rls: ["--tables", T1, "--principals", SA],
    }


MODS = [list_principals, apply_bypass_rls, apply_copilot_rls, rollback_rls]


@pytest.mark.parametrize("mod", MODS, ids=lambda m: m.__name__)
def test_au_01_flags_optional_and_auto_resolved(world, tmp_path, capsys, mod):
    code = mod.main(invocations(tmp_path)[mod])
    err = capsys.readouterr().err
    assert code == 0 and world.auth_calls == [(None, None)]
    assert "[AUTH] 执行账号: tester@x.com" in err and "quota 项目: fake-quota" in err


@pytest.mark.parametrize("mod", MODS, ids=lambda m: m.__name__)
def test_au_02_explicit_flags_passed_through(world, tmp_path, mod):
    mod.main(invocations(tmp_path)[mod] + ["--gcloud-account", "ops@x.com", "--quota-project", "qp"])
    assert world.auth_calls == [("ops@x.com", "qp")]


@pytest.mark.parametrize("mod", MODS, ids=lambda m: m.__name__)
@pytest.mark.parametrize("msg", [f"找不到可用的登录凭证。{gcp_auth.LOGIN_HINT}", f"无法确定 quota 项目。{gcp_auth.PROJECT_HINT}"])
def test_au_03_unresolvable_is_exit_2_with_hint(world, tmp_path, capsys, monkeypatch, mod, msg):
    def boom(*a, **k):
        raise gcp_auth.AuthConfigError(msg)
    monkeypatch.setattr(mod, "resolve_auth", boom)
    code = mod.main(invocations(tmp_path)[mod] + ["--apply"] if mod is not list_principals else invocations(tmp_path)[mod])
    err = capsys.readouterr().err
    assert code == 2 and world.ddl_log == [] and "[ERROR]" in err and "Traceback" not in err
    assert ("gcloud auth login" in err) or ("gcloud config set project" in err)


@pytest.mark.parametrize("mod", [apply_bypass_rls, apply_copilot_rls], ids=lambda m: m.__name__)
def test_au_04_old_project_flag_renamed(world, tmp_path, mod):
    with pytest.raises(SystemExit) as e:
        mod.main(invocations(tmp_path)[mod] + ["--project", "qp"])
    assert e.value.code == 2
