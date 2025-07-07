import os

from typing import Dict

class DatabaseConfig:
    """Database configuration settings"""
    
    def __init__(self):
        self.host = os.environ.get("DB_HOST", "localhost")
        self.database = os.environ.get("DB_NAME", "cisadb")
        self.user = os.environ.get("DB_USER", "postgres")
        self.password = os.environ.get("DB_PASSWORD", "1234")
        self.port = int(os.environ.get("DB_PORT", 5432))
    
    def get_connection_params(self) -> Dict:
        """Return connection parameters as dictionary"""
        return {
            "host": self.host,
            "database": self.database,
            "user": self.user,
            "password": self.password,
            "port": self.port
        }