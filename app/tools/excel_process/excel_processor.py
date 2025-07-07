import os
import logging
import datetime
import pandas as pd
import json
from typing import List, Optional, Dict, Any
from pathlib import Path

from tools.db.db_manager import DatabaseManager

logger = logging.getLogger("excel_processor")

class ExcelProcessor:
    """Enhanced Excel processor for PSVAR template analysis"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger("excel_processor")
        self.db_manager = DatabaseManager()
        
        # Default configuration
        self.config = {
            "psvarTemplatePath": "PSVAR Template.xlsx",
            "excelSheets": {
                "Analysis": [
                    "Review date (YYYY-MM-DD)",
                    "Component name",
                    "Component version", 
                    "Vulnerability ID (e.g. CVE)",
                    "Description",
                    "Base score",
                    "Exploitability",
                    "Impact",
                    "Remediation status",
                    "Remediation comment",
                    "Severity rating",
                    "Update PSSD?",
                    "Manage Defect requested?",
                    "Analysis Status",
                    "Analysis Justification",
                    "Analysis Response",
                    "Analysis Details",
                    "Analysis Internal Details"
                ],
                "Component overview": [
                    "Component name",
                    "Component version",
                    "Description",
                    "Support Status"
                ],
                "Summary": [
                    "Summary date",
                    "Summary description", 
                    "Summary status"
                ],
                "Title Page": [
                    {
                        "Scope": "<Scope Description, Refer PSRA template for more details>",
                        "Assessment team": "<Provide details of assessment team, Refer PSRA template for more details>"
                    }
                ]
            }
        }
        
        # Load custom config if provided
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)
    
    def load_config(self, config_path: str) -> bool:
        """Load Excel processing configuration from JSON file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                custom_config = json.load(f)
                self.config.update(custom_config)
            self.logger.info(f"Configuration loaded from {config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load config from {config_path}: {e}")
            return False
    
    def process_excel(self, file_path: str) -> Dict[str, Any]:
        """Process Excel file according to PSVAR template configuration"""
        if not os.path.exists(file_path):
            self.logger.error(f"Excel file not found: {file_path}")
            return {"success": False, "error": "File not found"}
        
        try:
            self.logger.info(f"Processing Excel file: {file_path}")
            
            # Read all sheets from the Excel file
            excel_data = pd.read_excel(file_path, sheet_name=None, engine='openpyxl')
            
            processed_data = {
                "file_path": file_path,
                "processed_at": datetime.datetime.now().isoformat(),
                "sheets": {},
                "analysis_summary": {},
                "vulnerabilities": [],
                "components": []
            }
            
            # Process each configured sheet
            for sheet_name, expected_columns in self.config["excelSheets"].items():
                if sheet_name in excel_data:
                    sheet_data = self._process_sheet(excel_data[sheet_name], sheet_name, expected_columns)
                    processed_data["sheets"][sheet_name] = sheet_data
                    
                    # Extract specific data based on sheet type
                    if sheet_name == "Analysis":
                        processed_data["vulnerabilities"] = self._extract_vulnerabilities(sheet_data)
                    elif sheet_name == "Component overview":
                        processed_data["components"] = self._extract_components(sheet_data)
                    elif sheet_name == "Summary":
                        processed_data["analysis_summary"] = self._extract_summary(sheet_data)
                else:
                    self.logger.warning(f"Expected sheet '{sheet_name}' not found in Excel file")
            
            # Enrich vulnerability data with database information
            if processed_data["vulnerabilities"]:
                processed_data["vulnerabilities"] = self._enrich_vulnerability_data(processed_data["vulnerabilities"])
            
            self.logger.info(f"Successfully processed Excel file with {len(processed_data['vulnerabilities'])} vulnerabilities and {len(processed_data['components'])} components")
            
            return {
                "success": True,
                "data": processed_data
            }
            
        except Exception as e:
            self.logger.error(f"Error processing Excel file {file_path}: {e}")
            return {"success": False, "error": str(e)}
    
    def _process_sheet(self, df: pd.DataFrame, sheet_name: str, expected_columns: List) -> Dict[str, Any]:
        """Process individual Excel sheet"""
        try:
            # Handle Title Page special case (dictionary structure)
            if sheet_name == "Title Page" and isinstance(expected_columns[0], dict):
                return self._process_title_page(df, expected_columns[0])
            
            # Standard sheet processing
            sheet_data = {
                "row_count": len(df),
                "column_count": len(df.columns),
                "columns_found": list(df.columns),
                "expected_columns": expected_columns,
                "missing_columns": [],
                "data": []
            }
            
            # Check for missing expected columns
            df_columns_lower = [col.lower().strip() for col in df.columns]
            for expected_col in expected_columns:
                expected_col_lower = expected_col.lower().strip()
                if expected_col_lower not in df_columns_lower:
                    sheet_data["missing_columns"].append(expected_col)
            
            # Convert DataFrame to list of dictionaries
            df_clean = df.dropna(how='all')  # Remove completely empty rows
            sheet_data["data"] = df_clean.to_dict('records')
            
            # Clean up NaN values
            for row in sheet_data["data"]:
                for key, value in row.items():
                    if pd.isna(value):
                        row[key] = None
            
            return sheet_data
            
        except Exception as e:
            self.logger.error(f"Error processing sheet '{sheet_name}': {e}")
            return {"error": str(e)}
    
    def _process_title_page(self, df: pd.DataFrame, expected_fields: Dict) -> Dict[str, Any]:
        """Process Title Page sheet with key-value pairs"""
        try:
            title_data = {
                "expected_fields": expected_fields,
                "extracted_data": {}
            }
            
            # Try to extract key-value pairs from the DataFrame
            for index, row in df.iterrows():
                for col in df.columns:
                    cell_value = row[col]
                    if pd.notna(cell_value) and isinstance(cell_value, str):
                        # Look for key-value patterns
                        for field_name in expected_fields.keys():
                            if field_name.lower() in cell_value.lower():
                                title_data["extracted_data"][field_name] = cell_value
            
            return title_data
            
        except Exception as e:
            self.logger.error(f"Error processing Title Page: {e}")
            return {"error": str(e)}
    
    def _extract_vulnerabilities(self, analysis_data: Dict) -> List[Dict]:
        """Extract vulnerability information from Analysis sheet"""
        vulnerabilities = []
        
        if "data" not in analysis_data:
            return vulnerabilities
        
        for row in analysis_data["data"]:
            # Skip rows without CVE information
            cve_id = self._find_value_by_key_pattern(row, ["vulnerability id", "cve"])
            if not cve_id or not str(cve_id).strip():
                continue
            
            vulnerability = {
                "cve_id": str(cve_id).strip(),
                "component_name": self._find_value_by_key_pattern(row, ["component name"]),
                "component_version": self._find_value_by_key_pattern(row, ["component version"]),
                "description": self._find_value_by_key_pattern(row, ["description"]),
                "base_score": self._find_value_by_key_pattern(row, ["base score"]),
                "exploitability": self._find_value_by_key_pattern(row, ["exploitability"]),
                "impact": self._find_value_by_key_pattern(row, ["impact"]),
                "severity_rating": self._find_value_by_key_pattern(row, ["severity rating"]),
                "remediation_status": self._find_value_by_key_pattern(row, ["remediation status"]),
                "remediation_comment": self._find_value_by_key_pattern(row, ["remediation comment"]),
                "analysis_status": self._find_value_by_key_pattern(row, ["analysis status"]),
                "analysis_justification": self._find_value_by_key_pattern(row, ["analysis justification"]),
                "analysis_response": self._find_value_by_key_pattern(row, ["analysis response"]),
                "analysis_details": self._find_value_by_key_pattern(row, ["analysis details"]),
                "review_date": self._find_value_by_key_pattern(row, ["review date"]),
                "update_pssd": self._find_value_by_key_pattern(row, ["update pssd"]),
                "manage_defect_requested": self._find_value_by_key_pattern(row, ["manage defect"])
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _extract_components(self, component_data: Dict) -> List[Dict]:
        """Extract component information from Component overview sheet"""
        components = []
        
        if "data" not in component_data:
            return components
        
        for row in component_data["data"]:
            component_name = self._find_value_by_key_pattern(row, ["component name"])
            if not component_name or not str(component_name).strip():
                continue
            
            component = {
                "name": str(component_name).strip(),
                "version": self._find_value_by_key_pattern(row, ["component version"]),
                "description": self._find_value_by_key_pattern(row, ["description"]),
                "support_status": self._find_value_by_key_pattern(row, ["support status"])
            }
            
            components.append(component)
        
        return components
    
    def _extract_summary(self, summary_data: Dict) -> Dict:
        """Extract summary information from Summary sheet"""
        summary = {
            "entries": [],
            "latest_summary": None
        }
        
        if "data" not in summary_data:
            return summary
        
        for row in summary_data["data"]:
            summary_desc = self._find_value_by_key_pattern(row, ["summary description"])
            if not summary_desc:
                continue
            
            entry = {
                "date": self._find_value_by_key_pattern(row, ["summary date"]),
                "description": summary_desc,
                "status": self._find_value_by_key_pattern(row, ["summary status"])
            }
            
            summary["entries"].append(entry)
        
        # Find latest summary entry
        if summary["entries"]:
            summary["latest_summary"] = summary["entries"][-1]
        
        return summary
    
    def _find_value_by_key_pattern(self, row: Dict, patterns: List[str]) -> Any:
        """Find value in row by matching key patterns (case-insensitive)"""
        for key, value in row.items():
            key_lower = str(key).lower().strip()
            for pattern in patterns:
                if pattern.lower() in key_lower:
                    return value
        return None
    
    def _enrich_vulnerability_data(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Enrich vulnerability data with KEV and EPSS information from database"""
        if not self.db_manager.connect():
            self.logger.warning("Could not connect to database for vulnerability enrichment")
            return vulnerabilities
        
        try:
            enriched_vulnerabilities = []
            
            for vuln in vulnerabilities:
                cve_id = vuln.get("cve_id")
                if not cve_id:
                    enriched_vulnerabilities.append(vuln)
                    continue
                
                # Get KEV data
                kev_data = self.db_manager.get_kev_data(cve_id)
                
                # Get EPSS data
                epss_data = self.db_manager.get_epss_data(cve_id)
                
                # Enrich vulnerability with database information
                enriched_vuln = vuln.copy()
                enriched_vuln.update({
                    "kev_info": kev_data,
                    "epss_info": epss_data,
                    "enriched_at": datetime.datetime.now().isoformat()
                })
                
                enriched_vulnerabilities.append(enriched_vuln)
            
            return enriched_vulnerabilities
            
        except Exception as e:
            self.logger.error(f"Error enriching vulnerability data: {e}")
            return vulnerabilities
        finally:
            self.db_manager.close()
    
    def export_processed_data(self, processed_data: Dict, output_path: str, format: str = "json") -> bool:
        """Export processed data to file"""
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            if format.lower() == "json":
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(processed_data, f, indent=2, default=str)
            elif format.lower() == "excel":
                # Export back to Excel format
                with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
                    for sheet_name, sheet_data in processed_data.get("sheets", {}).items():
                        if "data" in sheet_data and sheet_data["data"]:
                            df = pd.DataFrame(sheet_data["data"])
                            df.to_excel(writer, sheet_name=sheet_name, index=False)
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            self.logger.info(f"Processed data exported to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting processed data: {e}")
            return False
    
    def get_vulnerability_statistics(self, processed_data: Dict) -> Dict:
        """Generate statistics from processed vulnerability data"""
        vulnerabilities = processed_data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return {"total_vulnerabilities": 0}
        
        stats = {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_distribution": {},
            "remediation_status_distribution": {},
            "kev_vulnerabilities": 0,
            "high_epss_vulnerabilities": 0,
            "components_affected": set(),
            "analysis_status_distribution": {}
        }
        
        for vuln in vulnerabilities:
            # Severity distribution
            severity = vuln.get("severity_rating")
            if severity:
                stats["severity_distribution"][severity] = stats["severity_distribution"].get(severity, 0) + 1
            
            # Remediation status
            remediation = vuln.get("remediation_status")
            if remediation:
                stats["remediation_status_distribution"][remediation] = stats["remediation_status_distribution"].get(remediation, 0) + 1
            
            # Analysis status
            analysis_status = vuln.get("analysis_status")
            if analysis_status:
                stats["analysis_status_distribution"][analysis_status] = stats["analysis_status_distribution"].get(analysis_status, 0) + 1
            
            # KEV count
            if vuln.get("kev_info", {}).get("is_kev"):
                stats["kev_vulnerabilities"] += 1
            
            # High EPSS score (>0.7)
            epss_score = vuln.get("epss_info", {}).get("epss_score", 0)
            if epss_score > 0.7:
                stats["high_epss_vulnerabilities"] += 1
            
            # Components affected
            component = vuln.get("component_name")
            if component:
                stats["components_affected"].add(component)
        
        stats["unique_components_affected"] = len(stats["components_affected"])
        stats["components_affected"] = list(stats["components_affected"])
        
        return stats