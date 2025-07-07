import logging
import psycopg2

from typing import Dict

from tools.db.db_config import DatabaseConfig

class DatabaseManager:
    """Handles database connections and queries"""
    
    def __init__(self, config: DatabaseConfig = None):
        self.config = config or DatabaseConfig()
        self.connection = None
        self.logger = logging.getLogger("vuln_analyzer")
    
    def connect(self) -> bool:
        """Establish connection to the database"""
        try:
            self.connection = psycopg2.connect(**self.config.get_connection_params())
            self.logger.info("Successfully connected to the database")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            return False
    
    def close(self):
        """Close the database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def get_kev_data(self, cve_id: str) -> Dict:
        """Get KEV information for a CVE"""
        if not self.connection:
            self.logger.error("No database connection established")
            return {"is_kev": False, "error": "No database connection"}
            
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    SELECT cve_id, vendor_project, product, vulnerability_name, 
                           description, action, due_date, 
                           notes AS known_ransomware_campaign_use
                    FROM cisa_vulnerabilities
                    WHERE cve_id = %s
                """, (cve_id,))
                
                result = cur.fetchone()
                
                if result:
                    return {
                        "is_kev": True,
                        "cve_id": result[0],
                        "vendor_project": result[1],
                        "product": result[2],
                        "vulnerability_name": result[3],
                        "description": result[4],
                        "action": result[5],
                        "due_date": result[6].strftime('%Y-%m-%d') if result[6] else None,
                        "known_ransomware_campaign_use": result[7]
                    }
                else:
                    return {"is_kev": False}
                    
        except Exception as e:
            self.logger.error(f"Error fetching KEV data for {cve_id}: {e}")
            return {"is_kev": False, "error": str(e)}
    
    def get_epss_data(self, cve_id: str) -> Dict:
        """Get latest EPSS information for a CVE"""
        if not self.connection:
            self.logger.error("No database connection established")
            return {"epss_score": 0, "percentile": 0, "error": "No database connection"}
            
        try:
            with self.connection.cursor() as cur:
                cur.execute("""
                    SELECT cve_id, epss_score, percentile, date_recorded
                    FROM epss_scores
                    WHERE cve_id = %s
                    ORDER BY date_recorded DESC
                    LIMIT 1
                """, (cve_id,))
                result = cur.fetchone()
                
                if result:
                    return {
                        "cve_id": result[0],
                        "epss_score": result[1],
                        "percentile": result[2],
                        "date_recorded": result[3].strftime('%Y-%m-%d')
                    }
                else:
                    return {"epss_score": 0, "percentile": 0}
        except Exception as e:
            self.logger.error(f"Error fetching EPSS data for {cve_id}: {e}")
            return {"epss_score": 0, "percentile": 0, "error": str(e)}