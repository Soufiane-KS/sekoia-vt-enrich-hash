import requests_mock

from vtenrichhash_modules import VtenrichhashModule
from vtenrichhash_modules.action_vt_enrich_hash import VTEnrichHashAction
from vtenrichhash_modules.models import VtenrichhashModuleConfiguration


FAKE_API_KEY = "0123456789abcdef" * 4
FAKE_HASH = "44d88612fea8a8f36de82e1278abb02f"  # eicar test file MD5
VT_URL = f"https://www.virustotal.com/api/v3/files/{FAKE_HASH}"


def _make_action() -> VTEnrichHashAction:
    """Build an action wired to a module with a fake API key."""
    module = VtenrichhashModule()
    module.configuration = VtenrichhashModuleConfiguration(apikey=FAKE_API_KEY)
    return VTEnrichHashAction(module=module)


def _vt_response(malicious: int, undetected: int, malicious_vendors: list[str]) -> dict:
    """Build a fake VirusTotal v3 /files/{hash} response body."""
    results_map = {
        vendor: {"category": "malicious", "result": "Trojan.Generic"}
        for vendor in malicious_vendors
    }
    # pad with a few clean vendors so the total > malicious
    for vendor in [f"CleanAV{i}" for i in range(undetected)]:
        results_map[vendor] = {"category": "undetected", "result": None}

    return {
        "data": {
            "id": FAKE_HASH,
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "undetected": undetected,
                    "harmless": 0,
                    "suspicious": 0,
                    "timeout": 0,
                },
                "last_analysis_results": results_map,
            },
        }
    }


def test_malicious_branch():
    action = _make_action()
    body = _vt_response(malicious=3, undetected=67, malicious_vendors=["Avast", "Kaspersky", "Sophos"])

    with requests_mock.Mocker() as mock:
        mock.get(VT_URL, json=body, status_code=200)
        result = action.run({"hash": FAKE_HASH})

    assert result["verdict"] == "malicious"
    assert result["score"] == "3/70"
    assert set(result["malicious_vendors"]) == {"Avast", "Kaspersky", "Sophos"}
    assert result["permalink"] == f"https://www.virustotal.com/gui/file/{FAKE_HASH}"
    assert action.outputs == {"malicious": True}


def test_undetected_branch():
    action = _make_action()
    body = _vt_response(malicious=0, undetected=70, malicious_vendors=[])

    with requests_mock.Mocker() as mock:
        mock.get(VT_URL, json=body, status_code=200)
        result = action.run({"hash": FAKE_HASH})

    assert result["verdict"] == "undetected"
    assert result["score"] == "0/70"
    assert result["malicious_vendors"] == []
    assert action.outputs == {"undetected": True}


def test_unknown_branch_404():
    action = _make_action()

    with requests_mock.Mocker() as mock:
        mock.get(VT_URL, status_code=404)
        result = action.run({"hash": FAKE_HASH})

    assert result["verdict"] == "unknown"
    assert result["score"] == "0/0"
    assert result["malicious_vendors"] == []
    assert result["permalink"] == f"https://www.virustotal.com/gui/file/{FAKE_HASH}"
    assert action.outputs == {"unknown": True}


def test_request_sends_apikey_header():
    """The action must send the configured API key as the x-apikey header."""
    action = _make_action()
    body = _vt_response(malicious=0, undetected=70, malicious_vendors=[])

    with requests_mock.Mocker() as mock:
        mock.get(VT_URL, json=body, status_code=200)
        action.run({"hash": FAKE_HASH})

        assert mock.call_count == 1
        assert mock.request_history[0].headers["x-apikey"] == FAKE_API_KEY
