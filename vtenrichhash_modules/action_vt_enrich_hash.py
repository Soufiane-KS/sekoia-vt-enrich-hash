from pydantic.v1 import BaseModel
from sekoia_automation.action import Action
import requests


class VTEnrichHashArguments(BaseModel):
    hash: str


class VTEnrichHashResults(BaseModel):
    verdict: str          # "malicious", "undetected", or "unknown"
    score: str            
    malicious_vendors: list[str]
    permalink: str


class VTEnrichHashAction(Action):
    name = "VT Enrich Hash"
    description = "Enrich a file hash (MD5/SHA1/SHA256) via VirusTotal v3 API"
    results_model = VTEnrichHashResults

    def run(self, arguments: VTEnrichHashArguments) -> VTEnrichHashResults:
        api_key = self.module.configuration.apikey
        hash_value = arguments.hash

        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": api_key},
        )

        if response.status_code == 404:
            self.set_output("unknown", True)
            return VTEnrichHashResults(
                verdict="unknown",
                score="0/0",
                malicious_vendors=[],
                permalink=f"https://www.virustotal.com/gui/file/{hash_value}",
            )

        response.raise_for_status()
        data = response.json()["data"]
        stats = data["attributes"]["last_analysis_stats"]
        results_map = data["attributes"]["last_analysis_results"]

        malicious_count = stats.get("malicious", 0)
        total = sum(stats.values())
        score = f"{malicious_count}/{total}"

        malicious_vendors = [
            vendor
            for vendor, result in results_map.items()
            if result["category"] == "malicious"
        ]

        if malicious_count > 0:
            verdict = "malicious"
            self.set_output("malicious", True)
        else:
            verdict = "undetected"
            self.set_output("undetected", True)

        return VTEnrichHashResults(
            verdict=verdict,
            score=score,
            malicious_vendors=malicious_vendors,
            permalink=f"https://www.virustotal.com/gui/file/{data['id']}",
        )
