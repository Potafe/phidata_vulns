import logging
from typing import Dict, List, Tuple, Optional
from sentence_transformers import SentenceTransformer
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import re
from fuzzywuzzy import fuzz, process

logger = logging.getLogger("sbom_search")

class SBOMSearchEngine:
    """Enhanced SBOM search using semantic similarity and fuzzy matching"""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        self.component_embeddings = None
        self.component_texts = []
        self.components = []
        
    def index_sbom(self, sbom_data: Dict):
        """Create embeddings for all SBOM components"""
        if not sbom_data or 'components' not in sbom_data:
            logger.warning("No SBOM data or components found")
            return
        
        self.components = sbom_data.get('components', [])
        self.component_texts = []
        
        # Create searchable text for each component
        for component in self.components:
            component_text = self._create_component_text(component)
            self.component_texts.append(component_text)
        
        if self.component_texts:
            logger.info(f"Creating embeddings for {len(self.component_texts)} components")
            self.component_embeddings = self.model.encode(self.component_texts)
            logger.info("SBOM embeddings created successfully")
        
    def _create_component_text(self, component: Dict) -> str:
        """Create searchable text representation of a component"""
        parts = []
        
        # Component name (most important)
        name = component.get('name', '')
        if name:
            parts.append(name)
            
            # Extract artifact name from Maven/NPM coordinates
            if ':' in name:
                artifact = name.split(':')[-1]
                parts.append(artifact)
            if '/' in name:
                package = name.split('/')[-1]
                parts.append(package)
        
        # Version
        version = component.get('version', '')
        if version:
            parts.append(f"version {version}")
        
        # Package URL if available
        external_refs = component.get('externalRefs', [])
        for ref in external_refs:
            if ref.get('referenceType') == 'purl':
                purl = ref.get('referenceLocator', '')
                if purl:
                    parts.append(purl)
        
        # License information
        license_concluded = component.get('licenseConcluded', '')
        if license_concluded:
            parts.append(f"license {license_concluded}")
        
        return ' '.join(parts)
    
    def search_component(self, component_name: str, component_version: str = None) -> List[Dict]:
        """Search for component using multiple strategies"""
        if not self.components:
            return []
        
        search_results = []
        
        # Strategy 1: Exact name matching
        exact_matches = self._exact_name_search(component_name, component_version)
        search_results.extend(exact_matches)
        
        # Strategy 2: Fuzzy string matching
        fuzzy_matches = self._fuzzy_search(component_name, component_version)
        search_results.extend(fuzzy_matches)
        
        # Strategy 3: Semantic similarity search
        if self.component_embeddings is not None:
            semantic_matches = self._semantic_search(component_name, component_version)
            search_results.extend(semantic_matches)
        
        # Deduplicate and rank results
        ranked_results = self._rank_and_deduplicate(search_results, component_name, component_version)
        
        return ranked_results[:10]  # Return top 10 matches
    
    def _exact_name_search(self, component_name: str, component_version: str = None) -> List[Dict]:
        """Exact name matching with various formats"""
        matches = []
        component_lower = component_name.lower().strip()
        
        for i, component in enumerate(self.components):
            comp_name = str(component.get('name', '')).lower().strip()
            comp_version = str(component.get('version', '')).strip()
            
            match_score = 0
            match_type = ""
            
            # Direct match
            if comp_name == component_lower:
                match_score = 1.0
                match_type = "exact_name"
            
            # Substring match
            elif component_lower in comp_name:
                match_score = 0.9
                match_type = "substring"
            
            # Maven/NPM artifact extraction
            elif ':' in comp_name:
                artifact = comp_name.split(':')[-1].strip()
                if artifact == component_lower:
                    match_score = 0.95
                    match_type = "artifact_name"
            
            # Package name extraction
            elif '/' in comp_name:
                package = comp_name.split('/')[-1].strip()
                if package == component_lower:
                    match_score = 0.95
                    match_type = "package_name"
            
            if match_score > 0:
                # Version bonus
                if component_version and comp_version:
                    if comp_version == component_version:
                        match_score += 0.1
                        match_type += "_exact_version"
                
                matches.append({
                    'component': component,
                    'score': match_score,
                    'match_type': match_type,
                    'strategy': 'exact_name'
                })
        
        return matches
    
    def _fuzzy_search(self, component_name: str, component_version: str = None) -> List[Dict]:
        """Fuzzy string matching"""
        matches = []
        
        # Get component names for fuzzy matching
        component_names = [comp.get('name', '') for comp in self.components]
        
        # Find fuzzy matches
        fuzzy_results = process.extract(component_name, component_names, limit=5, scorer=fuzz.ratio)
        
        for match_name, score in fuzzy_results:
            if score >= 70:  # Minimum fuzzy score threshold
                # Find the component
                for component in self.components:
                    if component.get('name') == match_name:
                        normalized_score = score / 100.0 * 0.8  # Scale down fuzzy scores
                        
                        # Version bonus
                        comp_version = str(component.get('version', '')).strip()
                        if component_version and comp_version and comp_version == component_version:
                            normalized_score += 0.1
                        
                        matches.append({
                            'component': component,
                            'score': normalized_score,
                            'match_type': f"fuzzy_{score}",
                            'strategy': 'fuzzy'
                        })
                        break
        
        return matches
    
    def _semantic_search(self, component_name: str, component_version: str = None) -> List[Dict]:
        """Semantic similarity search using sentence transformers"""
        if self.component_embeddings is None:
            return []
        
        # Create query text
        query_parts = [component_name]
        if component_version:
            query_parts.append(f"version {component_version}")
        
        query_text = ' '.join(query_parts)
        query_embedding = self.model.encode([query_text])
        
        # Calculate similarities
        similarities = cosine_similarity(query_embedding, self.component_embeddings)[0]
        
        matches = []
        for i, similarity in enumerate(similarities):
            if similarity >= 0.6:  # Minimum semantic similarity threshold
                matches.append({
                    'component': self.components[i],
                    'score': similarity * 0.7,  # Scale down semantic scores
                    'match_type': f"semantic_{similarity:.3f}",
                    'strategy': 'semantic'
                })
        
        return matches
    
    def _rank_and_deduplicate(self, search_results: List[Dict], component_name: str, component_version: str = None) -> List[Dict]:
        """Rank and deduplicate search results"""
        # Deduplicate by component name
        seen_components = {}
        
        for result in search_results:
            comp_name = result['component'].get('name', '')
            
            if comp_name not in seen_components or result['score'] > seen_components[comp_name]['score']:
                seen_components[comp_name] = result
        
        # Sort by score (highest first)
        ranked_results = sorted(seen_components.values(), key=lambda x: x['score'], reverse=True)
        
        return ranked_results
    
    def analyze_component_presence(self, component_name: str, component_version: str = None) -> Dict:
        """Comprehensive component analysis"""
        search_results = self.search_component(component_name, component_version)
        
        analysis = {
            'total_components': len(self.components),
            'search_results': search_results,
            'top_matches': search_results[:3],
            'exact_matches': [r for r in search_results if r['score'] >= 0.95],
            'likely_matches': [r for r in search_results if 0.7 <= r['score'] < 0.95],
            'conclusion': self._determine_conclusion(search_results, component_name, component_version)
        }
        
        return analysis
    
    def _determine_conclusion(self, search_results: List[Dict], component_name: str, component_version: str = None) -> Dict:
        """Determine final conclusion based on search results"""
        if not search_results:
            return {
                'is_present': False,
                'confidence': 'HIGH',
                'reason': f'Component {component_name} not found in SBOM'
            }
        
        best_match = search_results[0]
        best_score = best_match['score']
        best_component = best_match['component']
        
        if best_score >= 0.95:
            # Check version match
            comp_version = str(best_component.get('version', '')).strip()
            if component_version and comp_version:
                if comp_version == component_version:
                    return {
                        'is_present': True,
                        'confidence': 'HIGH',
                        'reason': f'Exact match found: {component_name} v{component_version}',
                        'matched_component': best_component,
                        'match_score': best_score
                    }
                else:
                    return {
                        'is_present': True,
                        'confidence': 'MEDIUM',
                        'reason': f'Component {component_name} found but version mismatch. Found: {comp_version}, Looking for: {component_version}',
                        'matched_component': best_component,
                        'match_score': best_score
                    }
            else:
                return {
                    'is_present': True,
                    'confidence': 'HIGH',
                    'reason': f'Component {component_name} found in SBOM',
                    'matched_component': best_component,
                    'match_score': best_score
                }
        
        elif best_score >= 0.7:
            return {
                'is_present': True,
                'confidence': 'MEDIUM',
                'reason': f'Likely match found for {component_name} (score: {best_score:.3f})',
                'matched_component': best_component,
                'match_score': best_score
            }
        
        else:
            return {
                'is_present': False,
                'confidence': 'MEDIUM',
                'reason': f'No strong matches found for {component_name} (best score: {best_score:.3f})'
            }