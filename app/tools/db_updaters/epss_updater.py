import json
import logging
import schedule
import time
import os
from datetime import datetime, timedelta
import requests
import psycopg2
from psycopg2.extras import execute_values
from dateutil import parser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("epss_updater.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("epss_updater")

# Configuration
DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "localhost"),
    "database": os.environ.get("DB_NAME", "cisadb"),
    "user": os.environ.get("DB_USER", "postgres"),
    "password": os.environ.get("DB_PASSWORD", "1234"),
    "port": int(os.environ.get("DB_PORT", 5432))
}
EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
MAX_RETRIES = 5
RETRY_DELAY = 10  # seconds
BATCH_SIZE = 1000  # Number of records to insert at once

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
        CREATE TABLE IF NOT EXISTS epss_scores (
            id SERIAL PRIMARY KEY,
            cve_id TEXT NOT NULL,
            epss_score FLOAT NOT NULL,
            percentile FLOAT NOT NULL,
            date_recorded DATE NOT NULL,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(cve_id, date_recorded)
        )
        """)
        
        # Create index for faster lookups
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_epss_cve_id ON epss_scores(cve_id);
        CREATE INDEX IF NOT EXISTS idx_epss_score ON epss_scores(epss_score);
        CREATE INDEX IF NOT EXISTS idx_epss_date ON epss_scores(date_recorded);
        """)
        
        conn.commit()
        logger.info("EPSS tables created or already exist")

def fetch_epss_data(date=None, page_size=1000, max_pages=None):
    """Fetch vulnerability data from EPSS API with pagination"""
    all_data = []
    offset = 0
    page = 1
    
    url_params = {
        "envelope": "true",
        "limit": page_size,
    }
    
    if date:
        url_params["date"] = date
    
    while True:
        url_params["offset"] = offset
        
        try:
            logger.info(f"Fetching EPSS data page {page} (offset {offset})")
            response = requests.get(EPSS_BASE_URL, params=url_params)
            response.raise_for_status()
            data = response.json()
            
            # Check if we got any data
            current_page_data = data.get("data", [])
            if not current_page_data:
                logger.info("No more data to fetch")
                break
                
            all_data.extend(current_page_data)
            logger.info(f"Fetched {len(current_page_data)} records (total: {len(all_data)})")
            
            # Check if we've reached the maximum number of pages to fetch
            if max_pages and page >= max_pages:
                logger.info(f"Reached maximum number of pages ({max_pages})")
                break
                
            # Update offset for next page
            offset += page_size
            page += 1
            
            # Sleep briefly to avoid overwhelming the API
            time.sleep(1)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching EPSS data: {e}")
            break
    
    return all_data

def update_database():
    """Update the database with new EPSS data"""
    # Get today's date in YYYY-MM-DD format
    today = datetime.now().strftime("%Y-%m-%d")
    
    logger.info(f"Starting EPSS database update for {today}")
    
    if not wait_for_db():
        return False
    
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        create_tables(conn)
        
        # Fetch data for today
        epss_data = fetch_epss_data(date=today)
        
        if not epss_data:
            logger.warning("No EPSS data retrieved")
            return False
        
        # Process data in batches
        total_records = len(epss_data)
        logger.info(f"Processing {total_records} EPSS records")
        
        with conn.cursor() as cur:
            # Process in batches to avoid memory issues
            for i in range(0, total_records, BATCH_SIZE):
                batch = epss_data[i:i + BATCH_SIZE]
                
                # Prepare data for bulk insert/update
                values = []
                for item in batch:
                    values.append((
                        item.get("cve"),
                        float(item.get("epss", 0)),
                        float(item.get("percentile", 0)),
                        today,
                        datetime.now()
                    ))
                
                # Use execute_values for efficient bulk insert/update
                execute_values(cur, """
                INSERT INTO epss_scores 
                (cve_id, epss_score, percentile, date_recorded, last_updated)
                VALUES %s
                ON CONFLICT (cve_id, date_recorded) DO UPDATE SET
                    epss_score = EXCLUDED.epss_score,
                    percentile = EXCLUDED.percentile,
                    last_updated = EXCLUDED.last_updated
                """, values)
                
                logger.info(f"Processed batch {i//BATCH_SIZE + 1}/{(total_records + BATCH_SIZE - 1)//BATCH_SIZE}")
            
        conn.commit()
        logger.info(f"Database updated successfully with {total_records} EPSS records")
        return True
    
    except Exception as e:
        logger.error(f"Error updating database: {e}")
        if conn:
            conn.rollback()
        return False
    
    finally:
        if conn:
            conn.close()

def get_historical_data(days=30):
    """Fetch historical EPSS data for the last X days"""
    if not wait_for_db():
        return False
    
    conn = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        create_tables(conn)
        
        # Calculate dates
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        # Process each day
        current_date = start_date
        while current_date <= end_date:
            date_str = current_date.strftime("%Y-%m-%d")
            logger.info(f"Fetching historical EPSS data for {date_str}")
            
            # Check if we already have data for this date
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM epss_scores WHERE date_recorded = %s", (date_str,))
                count = cur.fetchone()[0]
                
                if count > 0:
                    logger.info(f"Data for {date_str} already exists ({count} records), skipping")
                else:
                    # Fetch data for this date
                    epss_data = fetch_epss_data(date=date_str)
                    
                    if epss_data:
                        # Process data in batches
                        total_records = len(epss_data)
                        logger.info(f"Processing {total_records} historical EPSS records for {date_str}")
                        
                        # Process in batches
                        for i in range(0, total_records, BATCH_SIZE):
                            batch = epss_data[i:i + BATCH_SIZE]
                            
                            # Prepare data for bulk insert
                            values = []
                            for item in batch:
                                values.append((
                                    item.get("cve"),
                                    float(item.get("epss", 0)),
                                    float(item.get("percentile", 0)),
                                    date_str,
                                    datetime.now()
                                ))
                            
                            # Bulk insert
                            execute_values(cur, """
                            INSERT INTO epss_scores 
                            (cve_id, epss_score, percentile, date_recorded, last_updated)
                            VALUES %s
                            ON CONFLICT (cve_id, date_recorded) DO NOTHING
                            """, values)
                            
                        conn.commit()
                        logger.info(f"Processed {total_records} historical records for {date_str}")
            
            # Move to next day
            current_date += timedelta(days=1)
            
            # Sleep to avoid overwhelming the API
            time.sleep(2)
            
        logger.info(f"Historical data update completed for the last {days} days")
        return True
        
    except Exception as e:
        logger.error(f"Error updating historical data: {e}")
        if conn:
            conn.rollback()
        return False
    
    finally:
        if conn:
            conn.close()

def update_job():
    """Main function to update the database"""
    logger.info("Starting EPSS update job")
    update_database()

def main():
    """Main entry point"""
    logger.info("Starting EPSS database updater")
    
    # Perform initial update
    update_job()
    
    # Get historical data (last 30 days)
    get_historical_data(days=30)
    
    # Set up scheduler for daily updates (at 1 AM)
    update_frequency = int(os.environ.get("UPDATE_FREQUENCY_HOURS", 24))
    
    if update_frequency > 0:
        schedule.every(update_frequency).hours.do(update_job)
        logger.info(f"Scheduler started. Will update EPSS database every {update_frequency} hours.")
        
        while True:
            schedule.run_pending()
            time.sleep(60)  # Sleep for 1 minute between checks
    else:
        logger.info("One-time run completed. Exiting.")

if __name__ == "__main__":
    main()