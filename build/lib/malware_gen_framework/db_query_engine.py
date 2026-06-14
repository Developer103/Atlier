"""
Wrapper that queries all 3 databases from within the framework.
Methods: query_malware_by_edr(), query_poc_by_cve(), query_findings_recent()
Uses subprocess to call existing query scripts.
"""

import subprocess
import json
import os
from typing import List, Optional
from .db_models import MalwareTechnique, PoC, CTIFinding, QueryResult

class DBQueryEngine:
    """Database query engine that interfaces with the three databases."""
    
    def __init__(self, malware_corpus_path: str = "/home/kei/llm_vault/malware_corpus", 
                 cti_db_path: str = "/home/kei/llm_vault/hermes_qwen_cti"):
        """
        Initialize the database query engine.
        
        Args:
            malware_corpus_path: Path to malware corpus directory
            cti_db_path: Path to CTI research database directory
        """
        self.malware_corpus_path = malware_corpus_path
        self.cti_db_path = cti_db_path
        
    def _run_query_malware(self, query: str, n_results: int = 10, **kwargs) -> List[MalwareTechnique]:
        """
        Query the malware technique corpus.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of MalwareTechnique objects
        """
        # Build command
        cmd = [
            "python3", 
            os.path.join(self.malware_corpus_path, "query_malware.py"),
            query,
            "-n", str(n_results),
            "--verbose"
        ]
        
        # Add optional flags if provided (accepts both --edr and edr)
        valid_flags = {"category", "os", "edr", "fullfile"}
        for key, value in kwargs.items():
            flag = f"--{key}" if not key.startswith("-") else key.strip("-")
            if flag in valid_flags:
                cmd.extend([f"--{flag}", str(value)])
                
        try:
            result = subprocess.run(cmd + ["--json"], capture_output=True, text=True, cwd=self.malware_corpus_path)
            if result.returncode == 0 and result.stdout.strip():
                # Parse JSON output
                data = json.loads(result.stdout)
                techniques = []
                for item in data:
                    technique = MalwareTechnique(
                        id=item.get("id"),
                        name=item.get("filename", ""),
                        description=item.get("description", ""),
                        category=item.get("category", ""),
                        os_type=item.get("target_os", ""),
                        edr_detection=item.get("edr_tags", ""),
                        detection_rating=round(1 - item.get("similarity", 0), 2),
                        references=[item.get("source_code", "")]
                    )
                    techniques.append(technique)
                return techniques
            else:
                # Return empty list on error
                print(f"Error in malware query (rc={result.returncode}): {result.stderr}")
                return []
        except Exception as e:
            print(f"Exception in malware query: {e}")
            return []
    
    def _run_query_poc(self, query: str, n_results: int = 10, **kwargs) -> List[PoC]:
        """
        Query the PoC corpus.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of PoC objects
        """
        # Build command
        cmd = [
            "python3", 
            os.path.join(self.malware_corpus_path, "query_poc.py"),
            query,
            "-n", str(n_results),
            "--verbose"
        ]
        
        try:
            result = subprocess.run(cmd + ["--json"], capture_output=True, text=True, cwd=self.malware_corpus_path)
            if result.returncode == 0 and result.stdout.strip():
                # Parse JSON output — direct list, not wrapped in "results" key
                data = json.loads(result.stdout)
                poc_list = []
                for item in data:
                    similarity = item.get("similarity", 0.5)
                    try:
                        sim_float = float(similarity)
                    except (ValueError, TypeError):
                        sim_float = 0.5
                    poc = PoC(
                        id=item.get("id"),
                        cve=item.get("cve", ""),
                        title=item.get("repo_name", ""),
                        description=item.get("description", ""),
                        exploit_type=item.get("language", ""),
                        target_os="",
                        severity="medium",
                        source=item.get("repo_url", ""),
                        code=item.get("description", "")[:500],
                        references=[item.get("filepath", "")]
                    )
                    poc_list.append(poc)
                return poc_list
            else:
                # Return empty list on error
                print(f"Error in PoC query (rc={result.returncode}): {result.stderr}")
                return []
        except Exception as e:
            print(f"Exception in PoC query: {e}")
            return []
    
    def _run_query_cti(self, query: str, n_results: int = 10) -> List[CTIFinding]:
        """
        Query the CTI knowledge base.
        
        Args:
            query: Search query
            n_results: Number of results to return
            
        Returns:
            List of CTIFinding objects
        """
        # Build command using the CTI database directory
        cmd = [
            "python3", 
            os.path.join(self.cti_db_path, "query_rag.py"),
            query,
            "-n", str(n_results)
        ]
        
        try:
            result = subprocess.run(cmd + ["--json"], capture_output=True, text=True, cwd=self.cti_db_path)
            if result.returncode == 0 and result.stdout.strip():
                # Parse JSON output — direct list from --json flag
                data = json.loads(result.stdout)
                findings = []
                for item in data:
                    references_list = item.get("references", [])
                    finding = CTIFinding(
                        id=item.get("id"),
                        title="",  # not available in CTI output
                        description=item.get("description", ""),
                        severity=item.get("severity", "medium"),
                        threat_actor="",
                        indicators=[],
                        related_cves=item.get("related_cves", []),
                        references=[references_list[0]] if isinstance(references_list, list) and references_list else [],
                    )
                    findings.append(finding)
                return findings
            else:
                # Return empty list on error
                print(f"Error in CTI query (rc={result.returncode}): {result.stderr}")
                return []
        except Exception as e:
            print(f"Exception in CTI query: {e}")
            return []
    
    def query_malware_by_edr(self, edr_list: List[str], n_results: int = 5) -> List[MalwareTechnique]:
        """
        Query malware techniques by EDR list.
        
        Args:
            edr_list: List of EDR names to search for
            n_results: Number of results per EDR
            
        Returns:
            List of MalwareTechnique objects matching the EDR criteria
        """
        all_techniques = []
        for edr in edr_list:
            techniques = self._run_query_malware(edr, n_results, edr=edr)
            all_techniques.extend(techniques)
        return all_techniques
    
    def query_poc_by_cve(self, cve_list: List[str], n_results: int = 5) -> List[PoC]:
        """
        Query PoCs by CVE list.
        
        Args:
            cve_list: List of CVE identifiers to search for
            n_results: Number of results per CVE
            
        Returns:
            List of PoC objects matching the CVE criteria
        """
        all_pocs = []
        for cve in cve_list:
            pocs = self._run_query_poc(cve, n_results)
            all_pocs.extend(pocs)
        return all_pocs
    
    def query_findings_recent(self, days: int = 7, n_results: int = 10) -> List[CTIFinding]:
        """
        Query recent findings from the CTI database.
        
        Args:
            days: Number of days to look back
            n_results: Number of results to return
            
        Returns:
            List of CTIFinding objects from recent reports
        """
        # This could be extended with a time-based query
        return self._run_query_cti("recent", n_results)
    
    def query_all(self, query: str, n_results: int = 10) -> QueryResult:
        """
        Perform all three types of queries with a single search term.
        
        Args:
            query: Search query to use for all databases
            n_results: Number of results per database
            
        Returns:
            QueryResult object containing results from all databases
        """
        # Run queries in parallel (or sequential - could be optimized)
        malware_techniques = self._run_query_malware(query, n_results)
        poc_results = self._run_query_poc(query, n_results)
        cti_findings = self._run_query_cti(query, n_results)
        
        return QueryResult(
            malware_techniques=malware_techniques,
            poc_results=poc_results,
            cti_findings=cti_findings
        )