import os
import git
import logging
import hashlib
import pickle
import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer
from dataclasses import dataclass
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Lexical search imports
try:
    from whoosh import index
    from whoosh.fields import Schema, TEXT, ID, STORED
    from whoosh.qparser import QueryParser
    from whoosh.filedb.filestore import RamStorage
    WHOOSH_AVAILABLE = True
except ImportError:
    logging.warning("Whoosh not available, lexical search will use basic text matching")
    WHOOSH_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class CodeChunk:
    """Represents a chunk of code with metadata"""
    content: str
    file_path: str
    start_line: int
    end_line: int
    language: str
    chunk_type: str  # 'function', 'class', 'import', 'config', 'general'
    hash: str

@dataclass
class SearchResult:
    """Search result from vector database or lexical search"""
    content: str
    file_path: str
    score: float
    metadata: Dict

class RepositoryProcessor:
    """Processes GitHub repositories and creates vector embeddings for code analysis"""
    
    def __init__(self, 
                 cache_dir: str = "./cache",
                 model_name: str = "all-MiniLM-L6-v2",
                 chunk_size: int = 500,
                 overlap_size: int = 50,
                 use_lexical_fallback: bool = True):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        
        self.model_name = model_name
        self.chunk_size = chunk_size
        self.overlap_size = overlap_size
        self.use_lexical_fallback = use_lexical_fallback
        
        # Initialize embedding model
        logger.info(f"Loading embedding model: {model_name}")
        try:
            self.embedding_model = SentenceTransformer(model_name)
            self.embedding_dim = self.embedding_model.get_sentence_embedding_dimension()
            self.embeddings_available = True
        except Exception as e:
            logger.error(f"Failed to load embedding model: {e}")
            self.embeddings_available = False
            self.embedding_model = None
            self.embedding_dim = 384  # Default dimension
        
        # Vector database
        self.vector_index = None
        self.chunks = []
        self.repo_metadata = {}
        
        # Lexical search
        self.lexical_index = None
        self.document_store = []
        
        # Supported file extensions for code analysis
        self.code_extensions = {
            '.py': 'python',
            '.js': 'javascript', 
            '.jsx': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.h': 'c',
            '.hpp': 'cpp',
            '.cs': 'csharp',
            '.go': 'go',
            '.rs': 'rust',
            '.php': 'php',
            '.rb': 'ruby',
            '.scala': 'scala',
            '.kt': 'kotlin',
            '.swift': 'swift',
            '.m': 'objective-c',
            '.sh': 'bash',
            '.yml': 'yaml',
            '.yaml': 'yaml',
            '.json': 'json',
            '.xml': 'xml',
            '.md': 'markdown',
            '.txt': 'text',
            '.dockerfile': 'dockerfile',
            '.sql': 'sql'
        }

    def clone_repository(self, repo_url: str, target_dir: Optional[str] = None) -> str:
        """Clone a GitHub repository to local directory"""
        if target_dir is None:
            repo_name = repo_url.split('/')[-1].replace('.git', '')
            target_dir = self.cache_dir / "repos" / repo_name
        
        target_path = Path(target_dir)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        
        if target_path.exists():
            logger.info(f"Repository already exists at {target_path}, pulling latest changes")
            try:
                repo = git.Repo(target_path)
                repo.remotes.origin.pull()
            except Exception as e:
                logger.warning(f"Failed to pull latest changes: {e}")
        else:
            logger.info(f"Cloning repository {repo_url} to {target_path}")
            try:
                git.Repo.clone_from(repo_url, target_path, depth=1)  # Shallow clone
            except Exception as e:
                logger.error(f"Failed to clone repository: {e}")
                raise
        
        return str(target_path)

    def extract_code_chunks(self, file_path: str) -> List[CodeChunk]:
        """Extract meaningful chunks from a code file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Failed to read file {file_path}: {e}")
            return []
        
        if not content.strip():
            return []
        
        file_ext = Path(file_path).suffix.lower()
        language = self.code_extensions.get(file_ext, 'text')
        
        chunks = []
        lines = content.split('\n')
        
        # For code files, try to extract semantic chunks
        if language in ['python', 'javascript', 'java', 'cpp', 'c']:
            chunks.extend(self._extract_semantic_chunks(lines, file_path, language))
        
        # For configuration and documentation files
        if language in ['yaml', 'json', 'markdown', 'text']:
            chunks.extend(self._extract_document_chunks(lines, file_path, language))
        
        # Fallback: sliding window chunking
        if not chunks:
            chunks.extend(self._extract_sliding_window_chunks(lines, file_path, language))
        
        return chunks

    def _extract_semantic_chunks(self, lines: List[str], file_path: str, language: str) -> List[CodeChunk]:
        """Extract semantic chunks like functions, classes, imports"""
        chunks = []
        current_chunk = []
        current_start = 0
        current_type = 'general'
        
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            
            # Detect chunk boundaries based on language
            is_boundary = False
            chunk_type = 'general'
            
            if language == 'python':
                if line_stripped.startswith(('def ', 'class ', 'async def ')):
                    is_boundary = True
                    chunk_type = 'function' if 'def ' in line_stripped else 'class'
                elif line_stripped.startswith(('import ', 'from ')):
                    chunk_type = 'import'
            elif language in ['javascript', 'typescript']:
                if re.match(r'^\s*(function|class|const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=)', line_stripped):
                    is_boundary = True
                    chunk_type = 'function'
                elif 'import' in line_stripped or 'require(' in line_stripped:
                    chunk_type = 'import'
            elif language == 'java':
                if re.match(r'^\s*(public|private|protected)?\s*(class|interface|enum)', line_stripped):
                    is_boundary = True
                    chunk_type = 'class'
                elif re.match(r'^\s*(public|private|protected)?\s*\w+.*\(.*\)\s*{', line_stripped):
                    is_boundary = True
                    chunk_type = 'function'
                elif 'import ' in line_stripped:
                    chunk_type = 'import'
            
            # If we hit a boundary and have accumulated content, create a chunk
            if is_boundary and current_chunk:
                chunk_content = '\n'.join(current_chunk)
                if chunk_content.strip():
                    chunks.append(self._create_chunk(
                        chunk_content, file_path, current_start, i-1, language, current_type
                    ))
                current_chunk = []
                current_start = i
                current_type = chunk_type
            
            current_chunk.append(line)
            
            # Also create chunks when they get too large
            if len(current_chunk) >= self.chunk_size:
                chunk_content = '\n'.join(current_chunk)
                chunks.append(self._create_chunk(
                    chunk_content, file_path, current_start, i, language, current_type
                ))
                # Overlap for continuity
                overlap_lines = current_chunk[-self.overlap_size:] if len(current_chunk) > self.overlap_size else current_chunk
                current_chunk = overlap_lines
                current_start = i - len(overlap_lines) + 1
        
        # Handle remaining content
        if current_chunk:
            chunk_content = '\n'.join(current_chunk)
            if chunk_content.strip():
                chunks.append(self._create_chunk(
                    chunk_content, file_path, current_start, len(lines)-1, language, current_type
                ))
        
        return chunks

    def _extract_document_chunks(self, lines: List[str], file_path: str, language: str) -> List[CodeChunk]:
        """Extract chunks from documentation and configuration files"""
        chunks = []
        current_chunk = []
        current_start = 0
        
        for i, line in enumerate(lines):
            current_chunk.append(line)
            
            # Create chunks based on size or logical boundaries
            if language == 'markdown':
                # Split on headers
                if line.strip().startswith('#') and current_chunk:
                    if len(current_chunk) > 1:  # Don't create single-line chunks
                        chunk_content = '\n'.join(current_chunk[:-1])
                        chunks.append(self._create_chunk(
                            chunk_content, file_path, current_start, i-1, language, 'section'
                        ))
                    current_chunk = [line]
                    current_start = i
            
            # Size-based chunking
            if len(current_chunk) >= self.chunk_size:
                chunk_content = '\n'.join(current_chunk)
                chunks.append(self._create_chunk(
                    chunk_content, file_path, current_start, i, language, 'content'
                ))
                current_chunk = []
                current_start = i + 1
        
        # Handle remaining content
        if current_chunk:
            chunk_content = '\n'.join(current_chunk)
            if chunk_content.strip():
                chunks.append(self._create_chunk(
                    chunk_content, file_path, current_start, len(lines)-1, language, 'content'
                ))
        
        return chunks

    def _extract_sliding_window_chunks(self, lines: List[str], file_path: str, language: str) -> List[CodeChunk]:
        """Fallback sliding window chunking"""
        chunks = []
        
        for i in range(0, len(lines), self.chunk_size - self.overlap_size):
            end_idx = min(i + self.chunk_size, len(lines))
            chunk_lines = lines[i:end_idx]
            
            if chunk_lines:
                chunk_content = '\n'.join(chunk_lines)
                if chunk_content.strip():
                    chunks.append(self._create_chunk(
                        chunk_content, file_path, i, end_idx-1, language, 'general'
                    ))
        
        return chunks

    def _create_chunk(self, content: str, file_path: str, start_line: int, end_line: int, language: str, chunk_type: str) -> CodeChunk:
        """Create a CodeChunk with hash"""
        content_hash = hashlib.md5(content.encode()).hexdigest()
        return CodeChunk(
            content=content,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            language=language,
            chunk_type=chunk_type,
            hash=content_hash
        )

    def process_repository(self, repo_path: str) -> Dict:
        """Process entire repository and extract code chunks"""
        repo_path = Path(repo_path)
        all_chunks = []
        file_count = 0
        
        logger.info(f"Processing repository: {repo_path}")
        
        # Walk through repository
        for root, dirs, files in os.walk(repo_path):
            # Skip common directories that don't contain relevant code
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'target', 'build', 'dist'}]
            
            for file in files:
                file_path = Path(root) / file
                file_ext = file_path.suffix.lower()
                
                # Only process supported file types
                if file_ext in self.code_extensions:
                    try:
                        chunks = self.extract_code_chunks(str(file_path))
                        all_chunks.extend(chunks)
                        file_count += 1
                        
                        if file_count % 100 == 0:
                            logger.info(f"Processed {file_count} files, extracted {len(all_chunks)} chunks")
                    except Exception as e:
                        logger.warning(f"Failed to process file {file_path}: {e}")
        
        logger.info(f"Repository processing complete: {file_count} files, {len(all_chunks)} chunks")
        
        return {
            'chunks': all_chunks,
            'file_count': file_count,
            'chunk_count': len(all_chunks),
            'repo_path': str(repo_path)
        }

    def create_embeddings(self, chunks: List[CodeChunk]) -> np.ndarray:
        """Create embeddings for code chunks"""
        if not chunks or not self.embeddings_available:
            return np.array([])
        
        logger.info(f"Creating embeddings for {len(chunks)} chunks")
        
        # Extract text content
        texts = [chunk.content for chunk in chunks]
        
        # Create embeddings in batches to manage memory
        batch_size = 100
        embeddings = []
        
        try:
            for i in range(0, len(texts), batch_size):
                batch_texts = texts[i:i + batch_size]
                batch_embeddings = self.embedding_model.encode(batch_texts, show_progress_bar=True)
                embeddings.append(batch_embeddings)
                
                if i % 1000 == 0:
                    logger.info(f"Created embeddings for {i + len(batch_texts)} chunks")
            
            return np.vstack(embeddings) if embeddings else np.array([])
        except Exception as e:
            logger.error(f"Failed to create embeddings: {e}")
            return np.array([])

    def build_vector_index(self, embeddings: np.ndarray) -> faiss.Index:
        """Build FAISS vector index"""
        if embeddings.size == 0:
            logger.warning("No embeddings provided, creating empty index")
            return faiss.IndexFlatIP(self.embedding_dim)
        
        logger.info(f"Building FAISS index with {embeddings.shape[0]} vectors")
        
        try:
            # Normalize embeddings for cosine similarity
            faiss.normalize_L2(embeddings)
            
            # Create index (using Inner Product for cosine similarity with normalized vectors)
            index = faiss.IndexFlatIP(embeddings.shape[1])
            index.add(embeddings.astype(np.float32))
            
            logger.info(f"FAISS index built successfully with {index.ntotal} vectors")
            return index
        except Exception as e:
            logger.error(f"Failed to build FAISS index: {e}")
            return faiss.IndexFlatIP(self.embedding_dim)

    def setup_lexical_index(self, chunks: List[CodeChunk]):
        """Setup lexical search index using Whoosh or fallback"""
        if not chunks:
            logger.warning("No chunks provided for lexical indexing")
            return
        
        self.document_store = []
        
        if WHOOSH_AVAILABLE:
            try:
                # Create schema
                schema = Schema(
                    id=ID(stored=True),
                    path=ID(stored=True),
                    content=TEXT(stored=True),
                    language=TEXT(stored=True),
                    chunk_type=TEXT(stored=True)
                )
                
                # Use RAM storage for simplicity
                storage = RamStorage()
                self.lexical_index = storage.create_index(schema)
                
                # Index documents
                writer = self.lexical_index.writer()
                for i, chunk in enumerate(chunks):
                    writer.add_document(
                        id=str(i),
                        path=chunk.file_path,
                        content=chunk.content,
                        language=chunk.language,
                        chunk_type=chunk.chunk_type
                    )
                    
                    self.document_store.append({
                        'content': chunk.content,
                        'file_path': chunk.file_path,
                        'metadata': {
                            'language': chunk.language,
                            'chunk_type': chunk.chunk_type,
                            'start_line': chunk.start_line,
                            'end_line': chunk.end_line,
                            'hash': chunk.hash
                        }
                    })
                
                writer.commit()
                logger.info(f"Lexical index created with {len(chunks)} documents")
                
            except Exception as e:
                logger.warning(f"Failed to create Whoosh index, using fallback: {e}")
                self._setup_fallback_lexical_index(chunks)
        else:
            self._setup_fallback_lexical_index(chunks)

    def _setup_fallback_lexical_index(self, chunks: List[CodeChunk]):
        """Setup simple in-memory lexical search"""
        self.document_store = []
        for chunk in chunks:
            self.document_store.append({
                'content': chunk.content,
                'file_path': chunk.file_path,
                'metadata': {
                    'language': chunk.language,
                    'chunk_type': chunk.chunk_type,
                    'start_line': chunk.start_line,
                    'end_line': chunk.end_line,
                    'hash': chunk.hash
                }
            })
        logger.info(f"Fallback lexical index created with {len(chunks)} documents")

    def semantic_search(self, query: str, top_k: int = 10, min_score: float = 0.1) -> List[SearchResult]:
        """Search for relevant code chunks using vector similarity"""
        if not self.embeddings_available or self.vector_index is None or len(self.chunks) == 0:
            logger.warning("Vector search not available, falling back to lexical search")
            return self.lexical_search(query, top_k)
        
        try:
            # Create query embedding
            query_embedding = self.embedding_model.encode([query])
            faiss.normalize_L2(query_embedding)
            
            # Search
            scores, indices = self.vector_index.search(query_embedding.astype(np.float32), top_k)
            
            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < len(self.chunks) and score >= min_score:
                    chunk = self.chunks[idx]
                    results.append(SearchResult(
                        content=chunk.content,
                        file_path=chunk.file_path,
                        score=float(score),
                        metadata={
                            'language': chunk.language,
                            'chunk_type': chunk.chunk_type,
                            'start_line': chunk.start_line,
                            'end_line': chunk.end_line,
                            'hash': chunk.hash
                        }
                    ))
            
            return results
            
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return self.lexical_search(query, top_k)

    def lexical_search(self, query: str, top_k: int = 10) -> List[SearchResult]:
        """Perform lexical search as fallback for large repositories"""
        if not self.document_store:
            return []
        
        results = []
        
        if WHOOSH_AVAILABLE and self.lexical_index:
            try:
                # Use Whoosh for lexical search
                with self.lexical_index.searcher() as searcher:
                    query_parser = QueryParser("content", self.lexical_index.schema)
                    parsed_query = query_parser.parse(query)
                    search_results = searcher.search(parsed_query, limit=top_k)
                    
                    for hit in search_results:
                        doc_id = int(hit['id'])
                        if doc_id < len(self.document_store):
                            doc = self.document_store[doc_id]
                            results.append(SearchResult(
                                content=doc['content'],
                                file_path=doc['file_path'],
                                score=hit.score if hasattr(hit, 'score') else 1.0,
                                metadata=doc['metadata']
                            ))
                
            except Exception as e:
                logger.warning(f"Whoosh search failed, using fallback: {e}")
                results = self._fallback_lexical_search(query, top_k)
        else:
            # Simple text matching fallback
            results = self._fallback_lexical_search(query, top_k)
        
        return results

    def _fallback_lexical_search(self, query: str, top_k: int = 10) -> List[SearchResult]:
        """Simple keyword-based search fallback"""
        query_lower = query.lower()
        scored_results = []
        
        for doc in self.document_store:
            content_lower = doc['content'].lower()
            
            # Calculate simple relevance score
            score = 0
            for word in query_lower.split():
                if word in content_lower:
                    score += content_lower.count(word) / len(content_lower.split())
            
            if score > 0:
                scored_results.append((score, doc))
        
        # Sort by score and limit results
        scored_results.sort(key=lambda x: x[0], reverse=True)
        
        results = []
        for score, doc in scored_results[:top_k]:
            results.append(SearchResult(
                content=doc['content'],
                file_path=doc['file_path'],
                score=score,
                metadata=doc['metadata']
            ))
        
        return results

    def save_index(self, index: faiss.Index, chunks: List[CodeChunk], repo_metadata: Dict, cache_key: str):
        """Save vector index and metadata to cache"""
        cache_dir = self.cache_dir / "indices" / cache_key
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Save FAISS index
            if index.ntotal > 0:
                index_path = cache_dir / "index.faiss"
                faiss.write_index(index, str(index_path))
            
            # Save chunks metadata
            chunks_path = cache_dir / "chunks.pkl"
            with open(chunks_path, 'wb') as f:
                pickle.dump(chunks, f)
            
            # Save repository metadata
            metadata_path = cache_dir / "metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(repo_metadata, f, indent=2)
            
            logger.info(f"Index and metadata saved to {cache_dir}")
            
        except Exception as e:
            logger.error(f"Failed to save index: {e}")

    def load_index(self, cache_key: str) -> Tuple[Optional[faiss.Index], List[CodeChunk], Dict]:
        """Load vector index and metadata from cache"""
        cache_dir = self.cache_dir / "indices" / cache_key
        
        if not cache_dir.exists():
            return None, [], {}
        
        try:
            # Load FAISS index
            index_path = cache_dir / "index.faiss"
            index = None
            if index_path.exists():
                index = faiss.read_index(str(index_path))
            
            # Load chunks
            chunks_path = cache_dir / "chunks.pkl"
            chunks = []
            if chunks_path.exists():
                with open(chunks_path, 'rb') as f:
                    chunks = pickle.load(f)
            
            # Load metadata
            metadata_path = cache_dir / "metadata.json"
            metadata = {}
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
            
            logger.info(f"Loaded index with {index.ntotal if index else 0} vectors and {len(chunks)} chunks")
            return index, chunks, metadata
            
        except Exception as e:
            logger.error(f"Failed to load cached index: {e}")
            return None, [], {}

    def setup_repository(self, repo_url: str, force_rebuild: bool = False) -> bool:
        """Complete setup: clone, process, and index repository"""
        try:
            # Generate cache key
            cache_key = hashlib.md5(repo_url.encode()).hexdigest()
            
            # Check cache first
            if not force_rebuild:
                index, chunks, metadata = self.load_index(cache_key)
                if index is not None or chunks:
                    self.vector_index = index
                    self.chunks = chunks
                    self.repo_metadata = metadata
                    
                    # Setup lexical search
                    self.setup_lexical_index(chunks)
                    
                    logger.info(f"Loaded cached index for repository {repo_url}")
                    return True
            
            # Clone repository
            repo_path = self.clone_repository(repo_url)
            
            # Process repository
            process_result = self.process_repository(repo_path)
            chunks = process_result['chunks']
            
            if not chunks:
                logger.warning("No code chunks extracted from repository")
                return False
            
            # Setup lexical search first (always available)
            self.setup_lexical_index(chunks)
            
            # Try to create vector embeddings
            embeddings = self.create_embeddings(chunks)
            
            # Build vector index
            index = self.build_vector_index(embeddings)
            
            # Save to cache
            repo_metadata = {
                'repo_url': repo_url,
                'repo_path': repo_path,
                'file_count': process_result['file_count'],
                'chunk_count': process_result['chunk_count'],
                'processed_at': str(datetime.datetime.now())
            }
            
            self.save_index(index, chunks, repo_metadata, cache_key)
            
            # Set instance variables
            self.vector_index = index
            self.chunks = chunks
            self.repo_metadata = repo_metadata
            
            logger.info(f"Repository setup complete for {repo_url}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup repository {repo_url}: {e}")
            return False

    def search_code(self, query: str, top_k: int = 10, prefer_semantic: bool = True) -> List[SearchResult]:
        """Search for relevant code using semantic or lexical search"""
        if prefer_semantic and self.embeddings_available:
            results = self.semantic_search(query, top_k)
            if results:
                return results
        
        # Fallback to lexical search
        return self.lexical_search(query, top_k)