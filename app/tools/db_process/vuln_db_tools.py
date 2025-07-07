import logging
import psycopg2
import os
from typing import Dict, List, Optional, Any
from phi.tools import Toolkit

logger = logging.getLogger(__name__)

class VulnerabilityDBTools(Toolkit):
    """Database tools for vulnerability analysis from CISA KEV and EPSS databases"""
    
    def __init__(self):
        super().__init__(name="vulnerability_db_tools")
        
        # Database configuration
        self.db_config = {
            "host": os.environ.get("DB_HOST", "localhost"),
            "database": os.environ.get("DB_NAME", "cisadb"),
            "user": os.environ.get("DB_USER", "postgres"),
            "password": os.environ.get("DB_PASSWORD", "1234"),
            "port": int(os.environ.get("DB_PORT", 5432))
        }
        
        # Register the functions as tools
        self.register(self.search_kev_database)
        self.register(self.get_epss_score)
        self.register(self.search_vulnerability_trends)
        self.register(self.get_database_statistics)
    
    def search_kev_database(self, cve_id: str) -> str:
        """Search CISA Known Exploited Vulnerabilities database for a specific CVE
        
        Args:
            cve_id: The CVE identifier to search for (e.g., CVE-2023-2976)
            
        Returns:
            String with KEV database search results and status
        """
        try:
            conn = psycopg2.connect(**self.db_config)
            
            with conn.cursor() as cur:
                # Search for the CVE in CISA KEV database
                cur.execute("""
                SELECT cve_id, vendor_project, product, vulnerability_name, description,
                       date_added, due_date, action, notes
                FROM cisa_vulnerabilities 
                WHERE UPPER(cve_id) = UPPER(%s)
                """, (cve_id,))
                
                result = cur.fetchone()
                
                if result:
                    kev_data = {
                        "cve_id": result[0],
                        "vendor_project": result[1],
                        "product": result[2],
                        "vulnerability_name": result[3],
                        "description": result[4],
                        "date_added": result[5].isoformat() if result[5] else None,
                        "due_date": result[6].isoformat() if result[6] else None,
                        "required_action": result[7],
                        "notes": result[8],
                        "kev_status": "LISTED_IN_KEV",
                        "priority": "HIGH - Known Exploited Vulnerability"
                    }
                    
                    logger.info(f"Found {cve_id} in CISA KEV database")
                    return f"KEV Database Result: {cve_id} is LISTED in CISA Known Exploited Vulnerabilities catalog. Details: {kev_data}"
                else:
                    logger.info(f"{cve_id} not found in CISA KEV database")
                    return f"KEV Database Result: {cve_id} is NOT listed in CISA Known Exploited Vulnerabilities catalog. This does not mean it's not exploitable, but it's not on the official KEV list."
            
        except Exception as e:
            logger.error(f"Error searching KEV database: {e}")
            return f"Error searching KEV database for {cve_id}: {str(e)}"
        
        finally:
            if 'conn' in locals():
                conn.close()
    
    def get_epss_score(self, cve_id: str, latest_only: bool = True) -> str:
        """Get EPSS score for a specific CVE
        
        Args:
            cve_id: The CVE identifier to get EPSS score for (e.g., CVE-2023-2976)
            latest_only: Whether to get only the latest score (default: True)
            
        Returns:
            String with EPSS score information and risk assessment
        """
        try:
            conn = psycopg2.connect(**self.db_config)
            
            with conn.cursor() as cur:
                if latest_only:
                    # Get the most recent EPSS score
                    cur.execute("""
                    SELECT cve_id, epss_score, percentile, date_recorded
                    FROM epss_scores 
                    WHERE UPPER(cve_id) = UPPER(%s)
                    ORDER BY date_recorded DESC
                    LIMIT 1
                    """, (cve_id,))
                    
                    result = cur.fetchone()
                else:
                    # Get all EPSS scores for historical analysis
                    cur.execute("""
                    SELECT cve_id, epss_score, percentile, date_recorded
                    FROM epss_scores 
                    WHERE UPPER(cve_id) = UPPER(%s)
                    ORDER BY date_recorded DESC
                    LIMIT 30
                    """, (cve_id,))
                    
                    result = cur.fetchall()
                
                if result:
                    if latest_only:
                        epss_data = {
                            "cve_id": result[0],
                            "epss_score": float(result[1]),
                            "percentile": float(result[2]),
                            "date_recorded": result[3].isoformat() if result[3] else None,
                            "exploitation_probability": f"{float(result[1]) * 100:.2f}%",
                            "risk_level": self._categorize_epss_score(float(result[1]))
                        }
                        
                        logger.info(f"Found EPSS score for {cve_id}: {epss_data['epss_score']}")
                        return f"EPSS Score Result: {cve_id} has EPSS score of {epss_data['epss_score']} ({epss_data['exploitation_probability']} probability of exploitation) at {epss_data['percentile']} percentile. Risk Level: {epss_data['risk_level']}. Date: {epss_data['date_recorded']}"
                    else:
                        # Historical analysis
                        scores = []
                        for r in result:
                            scores.append({
                                "date": r[3].isoformat() if r[3] else None,
                                "score": float(r[1]),
                                "percentile": float(r[2])
                            })
                        
                        latest_score = scores[0]['score'] if scores else 0
                        return f"EPSS Historical Data: {cve_id} has {len(scores)} EPSS records. Latest score: {latest_score} ({latest_score * 100:.2f}% exploitation probability). Historical data available for trend analysis."
                else:
                    logger.info(f"No EPSS score found for {cve_id}")
                    return f"EPSS Score Result: No EPSS score found for {cve_id}. This CVE may be too new or not in the EPSS database."
            
        except Exception as e:
            logger.error(f"Error getting EPSS score: {e}")
            return f"Error retrieving EPSS score for {cve_id}: {str(e)}"
        
        finally:
            if 'conn' in locals():
                conn.close()
    
    def search_vulnerability_trends(self, component_name: str, limit: int = 10) -> str:
        """Search for vulnerability trends for a specific component
        
        Args:
            component_name: The component name to search for trends
            limit: Maximum number of results to return (default: 10)
            
        Returns:
            String with vulnerability trends for the component
        """
        try:
            conn = psycopg2.connect(**self.db_config)
            
            with conn.cursor() as cur:
                # Search for vulnerabilities related to the component
                cur.execute("""
                SELECT cve_id, vendor_project, product, vulnerability_name, date_added
                FROM cisa_vulnerabilities 
                WHERE LOWER(vendor_project) LIKE LOWER(%s) 
                   OR LOWER(product) LIKE LOWER(%s)
                ORDER BY date_added DESC
                LIMIT %s
                """, (f"%{component_name}%", f"%{component_name}%", limit))
                
                results = cur.fetchall()
                
                if results:
                    trends = []
                    for result in results:
                        trends.append({
                            "cve_id": result[0],
                            "vendor_project": result[1],
                            "product": result[2],
                            "vulnerability_name": result[3],
                            "date_added": result[4].isoformat() if result[4] else None
                        })
                    
                    logger.info(f"Found {len(trends)} related vulnerabilities for {component_name}")
                    return f"Component Vulnerability Trends: Found {len(trends)} vulnerabilities related to {component_name} in CISA KEV database: {trends}"
                else:
                    return f"Component Vulnerability Trends: No vulnerabilities found for {component_name} in CISA KEV database."
            
        except Exception as e:
            logger.error(f"Error searching vulnerability trends: {e}")
            return f"Error searching vulnerability trends for {component_name}: {str(e)}"
        
        finally:
            if 'conn' in locals():
                conn.close()
    
    def get_database_statistics(self) -> str:
        """Get database statistics and health information
        
        Returns:
            String with database statistics and health status
        """
        try:
            conn = psycopg2.connect(**self.db_config)
            
            with conn.cursor() as cur:
                # Get KEV statistics
                cur.execute("SELECT COUNT(*) FROM cisa_vulnerabilities")
                kev_count = cur.fetchone()[0]
                
                # Get EPSS statistics
                cur.execute("SELECT COUNT(*) FROM epss_scores")
                epss_count = cur.fetchone()[0]
                
                # Get latest dates
                cur.execute("SELECT MAX(date_added) FROM cisa_vulnerabilities")
                latest_kev = cur.fetchone()[0]
                
                cur.execute("SELECT MAX(date_recorded) FROM epss_scores")
                latest_epss = cur.fetchone()[0]
                
                stats = {
                    "kev_vulnerabilities": kev_count,
                    "epss_scores": epss_count,
                    "latest_kev_date": latest_kev.isoformat() if latest_kev else None,
                    "latest_epss_date": latest_epss.isoformat() if latest_epss else None,
                    "database_status": "healthy"
                }
                
                return f"Database Statistics: {stats}"
            
        except Exception as e:
            logger.error(f"Error getting database statistics: {e}")
            return f"Error getting database statistics: {str(e)}"
        
        finally:
            if 'conn' in locals():
                conn.close()
    
    def test_connection(self) -> bool:
        """Test database connection"""
        try:
            conn = psycopg2.connect(**self.db_config)
            conn.close()
            logger.info("Database connection test successful")
            return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def _categorize_epss_score(self, score: float) -> str:
        """Categorize EPSS score into risk levels"""
        if score >= 0.7:
            return "CRITICAL"
        elif score >= 0.5:
            return "HIGH"
        elif score >= 0.3:
            return "MEDIUM"
        elif score >= 0.1:
            return "LOW"
        else:
            return "VERY_LOW"