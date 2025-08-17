"""
Database Manager for ATous Secure Network

This module handles database connections, initialization, and basic operations
"""

import os
import logging
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
from typing import Optional, Generator
import threading

from .models import Base

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and operations"""
    
    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize database manager
        
        Args:
            database_url: Database connection URL. If None, uses default SQLite
        """
        self.database_url = database_url or self._get_default_database_url()
        self.engine = None
        self.SessionLocal = None
        self._lock = threading.Lock()
        
        logger.info(f"Initializing database manager with URL: {self.database_url}")
    
    def _get_default_database_url(self) -> str:
        """Get default database URL for development"""
        # Use SQLite for development by default
        db_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'atous_network.db')
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        return f"sqlite:///{db_path}"
    
    def initialize(self) -> bool:
        """
        Initialize database connection and create tables
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            with self._lock:
                if self.engine is not None:
                    logger.info("Database already initialized")
                    return True
                
                # Create engine
                if self.database_url.startswith('sqlite'):
                    # SQLite specific configuration
                    self.engine = create_engine(
                        self.database_url,
                        connect_args={'check_same_thread': False},
                        poolclass=StaticPool,
                        echo=False  # Set to True for SQL debugging
                    )
                else:
                    # PostgreSQL/MySQL configuration
                    self.engine = create_engine(
                        self.database_url,
                        pool_pre_ping=True,
                        pool_recycle=300,
                        echo=False
                    )
                
                # Create session factory
                self.SessionLocal = sessionmaker(
                    autocommit=False,
                    autoflush=False,
                    bind=self.engine
                )
                
                # Create tables
                self.create_tables()
                
                logger.info("Database initialized successfully")
                return True
                
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            return False
    
    def create_tables(self):
        """Create all database tables"""
        try:
            Base.metadata.create_all(bind=self.engine)
            logger.info("Database tables created successfully")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise
    
    def drop_tables(self):
        """Drop all database tables (use with caution!)"""
        try:
            Base.metadata.drop_all(bind=self.engine)
            logger.warning("All database tables dropped")
        except Exception as e:
            logger.error(f"Failed to drop tables: {e}")
            raise
    
    @contextmanager
    def get_session(self) -> Generator:
        """
        Get database session context manager
        
        Yields:
            Database session
        """
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()
    
    def get_session_sync(self):
        """Get database session (synchronous)"""
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return self.SessionLocal()
    
    def test_connection(self) -> bool:
        """
        Test database connection
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            with self.get_session() as session:
                # Simple query to test connection
                session.execute("SELECT 1")
                return True
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
    
    def close(self):
        """Close database connections"""
        try:
            if self.engine:
                self.engine.dispose()
                self.engine = None
                self.SessionLocal = None
                logger.info("Database connections closed")
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Global database manager instance
_db_manager: Optional[DatabaseManager] = None


def get_database_manager() -> DatabaseManager:
    """Get global database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager


def initialize_database(database_url: Optional[str] = None) -> bool:
    """
    Initialize global database manager
    
    Args:
        database_url: Optional database URL
        
    Returns:
        True if initialization successful
    """
    global _db_manager
    _db_manager = DatabaseManager(database_url)
    return _db_manager.initialize()


def close_database():
    """Close global database manager"""
    global _db_manager
    if _db_manager:
        _db_manager.close()
        _db_manager = None
