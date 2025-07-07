import json
import logging
import schedule
import time
import os
from datetime import datetime
import requests
import psycopg2
from psycopg2.extras import execute_values
from dateutil import parser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("cisa_updater.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("cisa_updater")

# Configuration
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "database": os.environ.get("DB_NAME", "cisadb"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", "1234"),
    "port": int(os.environ.get("DB_PORT", 5432))
}
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_RETRIES = 5
RETRY_DELAY = 10  # seconds

def wait_for_db():
    """Wait for database to become available"""
    retries = 0
    while retries < MAX_RETRIES:
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.close()
            logger.info("Database connection successful")
            return True
        except psycopg2.OperationalError as e:
            retries += 1
            logger.warning(f"Database connection attempt {retries}/{MAX_RETRIES} failed: {e}")
            if retries < MAX_RETRIES:
                logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
    
    logger.error("Could not connect to database after multiple attempts")
    return False

def create_tables(conn):
    """Create necessary tables if they don't exist"""
    with conn.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cisa_catalog_info (
            id SERIAL PRIMARY KEY,
            title TEXT,
            catalog_version TEXT,
            date_released TIMESTAMP,
            count INTEGER
        )
        """)
        
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cisa_vulnerabilities (
            id SERIAL PRIMARY KEY,
            cve_id TEXT UNIQUE,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            description TEXT,
            date_added TIMESTAMP,
            due_date TIMESTAMP,
            action TEXT,
            notes TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()
        logger.info("Tables created or already exist")

def fetch_cisa_data():
    """Fetch vulnerability data from CISA"""
    try:
        response = requests.get(CISA_URL)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching data: {e}")
        return None

def update_database(data):
    """Update the database with new vulnerability data"""
    if not data:
        return False
    
    if not wait_for_db():
        return False
    
    conn = None  # Initialize conn to avoid UnboundLocalError
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        create_tables(conn)
        
        # Update catalog info
        with conn.cursor() as cur:
            cur.execute("""
            INSERT INTO cisa_catalog_info (title, catalog_version, date_released, count)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                catalog_version = EXCLUDED.catalog_version,
                date_released = EXCLUDED.date_released,
                count = EXCLUDED.count
            """, (
                data.get("title"),
                data.get("catalogVersion"),  # Changed from catalog.get("version")
                parser.parse(data.get("dateReleased")) if data.get("dateReleased") else None,  # Changed from catalog.get("dateReleased")
                len(data.get("vulnerabilities", []))
            ))
        
        # Update vulnerabilities
        with conn.cursor() as cur:
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Prepare data for bulk insert/update
            values = []
            for vuln in vulnerabilities:
                values.append((
                    vuln.get("cveID"),
                    vuln.get("vendorProject"),
                    vuln.get("product"),
                    vuln.get("vulnerabilityName"),
                    vuln.get("shortDescription"),
                    parser.parse(vuln.get("dateAdded")) if vuln.get("dateAdded") else None,
                    parser.parse(vuln.get("dueDate")) if vuln.get("dueDate") else None,
                    vuln.get("requiredAction"),
                    vuln.get("notes"),
                    datetime.now()
                ))
            
            # Use execute_values for efficient bulk insert/update
            execute_values(cur, """
            INSERT INTO cisa_vulnerabilities 
            (cve_id, vendor_project, product, vulnerability_name, description, 
             date_added, due_date, action, notes, last_updated)
            VALUES %s
            ON CONFLICT (cve_id) DO UPDATE SET
                vendor_project = EXCLUDED.vendor_project,
                product = EXCLUDED.product,
                vulnerability_name = EXCLUDED.vulnerability_name,
                description = EXCLUDED.description,
                date_added = EXCLUDED.date_added,
                due_date = EXCLUDED.due_date,
                action = EXCLUDED.action,
                notes = EXCLUDED.notes,
                last_updated = EXCLUDED.last_updated
            """, values)
            
        conn.commit()
        logger.info(f"Database updated successfully with {len(data.get('vulnerabilities', []))} vulnerabilities")
        return True
    
    except (Exception, psycopg2.Error) as e:
        logger.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def update_job():
    """Main function to update the database"""
    logger.info("Starting CISA vulnerability database update")
    data = fetch_cisa_data()
    success = update_database(data)
    if success:
        logger.info("Update completed successfully")
    else:
        logger.error("Update failed")

def main():
    """Run the script and set up scheduling"""
    # Run once at startup
    update_job()
    
    # Schedule to run daily at midnight
    schedule.every().day.at("00:00").do(update_job)
    
    logger.info("Scheduler started. Will update database daily at midnight.")
    
    # Keep the script running
    while True:
        schedule.run_pending()
        time.sleep(60)

if __name__ == "__main__":
    main()