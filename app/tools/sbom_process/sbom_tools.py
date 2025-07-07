import logging
from typing import Dict, List, Any, Optional
from phi.tools import Toolkit
from .sbom_search import SBOMSearchEngine

logger = logging.getLogger(__name__)

class SBOMTools(Toolkit):
    """Enhanced SBOM analysis tools with real search capabilities"""
    
    def __init__(self):
        super().__init__(name="sbom_tools")
        self.sbom_data = None
        self.search_engine = SBOMSearchEngine()
        self.sbom_loaded = False
    
    def set_sbom_data(self, sbom_data: Dict):
        """Set SBOM data and initialize search engine"""
        try:
            self.sbom_data = sbom_data
            logger.info(f"Indexing SBOM with {len(sbom_data.get('components', []))} components")
            
            # Index SBOM for search
            self.search_engine.index_sbom(sbom_data)
            self.sbom_loaded = True
            
            logger.info("SBOM search engine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to set SBOM data: {e}")
            self.sbom_loaded = False
    
    def analyze_sbom(self, component_name: str, component_version: str = None) -> Dict:
        """Analyze SBOM for specific component with detailed logging"""
        logger.info(f"SBOM ANALYSIS: Searching for component '{component_name}' version '{component_version}'")
        
        if not self.sbom_loaded:
            logger.error("SBOM not loaded - cannot perform analysis")
            return {
                "status": "error",
                "message": "SBOM data not loaded",
                "component_found": False,
                "search_performed": False
            }
        
        try:
            # Perform comprehensive component analysis
            logger.info(f"Starting comprehensive search across {len(self.sbom_data.get('components', []))} components")
            
            analysis_result = self.search_engine.analyze_component_presence(component_name, component_version)
            
            # Log search details
            logger.info(f"     Search strategies used:")
            logger.info(f"     - Exact name matching")
            logger.info(f"     - Fuzzy string matching") 
            logger.info(f"     - Semantic similarity search")
            
            # Log results summary
            total_results = len(analysis_result.get('search_results', []))
            exact_matches = len(analysis_result.get('exact_matches', []))
            likely_matches = len(analysis_result.get('likely_matches', []))
            
            logger.info(f"     Search Results Summary:")
            logger.info(f"     - Total matches found: {total_results}")
            logger.info(f"     - Exact matches: {exact_matches}")
            logger.info(f"     - Likely matches: {likely_matches}")
            
            # Log top matches
            top_matches = analysis_result.get('top_matches', [])
            if top_matches:
                logger.info(f"Top Matches:")
                for i, match in enumerate(top_matches[:3], 1):
                    comp = match['component']
                    score = match['score']
                    match_type = match['match_type']
                    logger.info(f"     {i}. {comp.get('name', 'Unknown')} v{comp.get('version', 'Unknown')} (Score: {score:.3f}, Type: {match_type})")
            
            # Log conclusion
            conclusion = analysis_result.get('conclusion', {})
            is_present = conclusion.get('is_present', False)
            confidence = conclusion.get('confidence', 'UNKNOWN')
            reason = conclusion.get('reason', 'No reason provided')
            
            logger.info(f"      Final Conclusion:")
            logger.info(f"     - Component Present: {'YES' if is_present else 'NO'}")
            logger.info(f"     - Confidence Level: {confidence}")
            logger.info(f"     - Reasoning: {reason}")
            
            # Determine vulnerability status
            vulnerability_analysis = self._analyze_vulnerability_status(
                component_name, component_version, analysis_result
            )
            
            # Log vulnerability analysis
            logger.info(f"       Vulnerability Analysis:")
            logger.info(f"     - Version Vulnerable: {'YES' if vulnerability_analysis['version_vulnerable'] else 'NO'}")
            logger.info(f"     - Risk Level: {vulnerability_analysis['risk_level']}")
            
            return {
                "status": "success",
                "component_name": component_name,
                "component_version": component_version,
                "component_found": is_present,
                "confidence": confidence,
                "search_summary": {
                    "total_matches": total_results,
                    "exact_matches": exact_matches,
                    "likely_matches": likely_matches,
                    "top_match": top_matches[0] if top_matches else None
                },
                "vulnerability_analysis": vulnerability_analysis,
                "conclusion": conclusion,
                "detailed_results": analysis_result,
                "search_performed": True,
                "sbom_stats": {
                    "total_components": len(self.sbom_data.get('components', [])),
                    "search_strategies": ["exact_name", "fuzzy_matching", "semantic_similarity"]
                }
            }
            
        except Exception as e:
            logger.error(f"SBOM analysis failed for {component_name}: {e}")
            return {
                "status": "error",
                "message": str(e),
                "component_found": False,
                "search_performed": False
            }
    
    def _analyze_vulnerability_status(self, component_name: str, component_version: str, search_results: Dict) -> Dict:
        """Analyze if the found component version is vulnerable"""
        
        conclusion = search_results.get('conclusion', {})
        is_present = conclusion.get('is_present', False)
        
        if not is_present:
            return {
                "version_vulnerable": False,
                "risk_level": "none",
                "reason": "Component not present in SBOM",
                "version_comparison": "N/A"
            }
        
        matched_component = conclusion.get('matched_component', {})
        found_version = matched_component.get('version', '')
        
        # Version comparison logic
        if component_version and found_version:
            if found_version == component_version:
                return {
                    "version_vulnerable": True,
                    "risk_level": "high",
                    "reason": f"Exact version match - {found_version} is vulnerable",
                    "version_comparison": "exact_match",
                    "found_version": found_version,
                    "expected_version": component_version
                }
            else:
                # Simple version comparison (can be enhanced)
                return {
                    "version_vulnerable": True,  # Conservative approach
                    "risk_level": "medium",
                    "reason": f"Version mismatch - found {found_version}, expected {component_version}",
                    "version_comparison": "version_mismatch",
                    "found_version": found_version,
                    "expected_version": component_version
                }
        else:
            return {
                "version_vulnerable": True,  # Conservative approach when version unclear
                "risk_level": "medium",
                "reason": "Component found but version comparison unclear",
                "version_comparison": "unclear",
                "found_version": found_version,
                "expected_version": component_version
            }
    
    def get_sbom_statistics(self) -> Dict:
        """Get comprehensive SBOM statistics"""
        if not self.sbom_loaded:
            return {"status": "error", "message": "SBOM not loaded"}
        
        components = self.sbom_data.get('components', [])
        
        # Analyze component types
        license_info = {}
        version_info = {}
        name_patterns = {}
        
        for comp in components:
            # License analysis
            license_concluded = comp.get('licenseConcluded', 'Unknown')
            license_info[license_concluded] = license_info.get(license_concluded, 0) + 1
            
            # Version analysis
            version = comp.get('version', 'Unknown')
            version_info[version] = version_info.get(version, 0) + 1
            
            # Name pattern analysis
            name = comp.get('name', '')
            if ':' in name:
                name_patterns['maven'] = name_patterns.get('maven', 0) + 1
            elif '/' in name:
                name_patterns['npm'] = name_patterns.get('npm', 0) + 1
            else:
                name_patterns['other'] = name_patterns.get('other', 0) + 1
        
        return {
            "status": "success",
            "total_components": len(components),
            "license_distribution": license_info,
            "version_distribution": dict(list(version_info.items())[:10]),  # Top 10
            "name_patterns": name_patterns,
            "search_engine_ready": self.search_engine.component_embeddings is not None
        }
    
    def search_components_by_pattern(self, pattern: str) -> Dict:
        """Search components using a pattern with detailed logging"""
        logger.info(f"PATTERN SEARCH: Searching components with pattern '{pattern}'")
        
        if not self.sbom_loaded:
            return {"status": "error", "message": "SBOM not loaded"}
        
        try:
            matching_components = []
            components = self.sbom_data.get('components', [])
            
            logger.info(f"Searching through {len(components)} components")
            
            for comp in components:
                name = comp.get('name', '').lower()
                if pattern.lower() in name:
                    matching_components.append({
                        'name': comp.get('name', ''),
                        'version': comp.get('version', ''),
                        'licenseConcluded': comp.get('licenseConcluded', '')
                    })
            
            logger.info(f"Found {len(matching_components)} components matching pattern '{pattern}'")
            
            if matching_components:
                logger.info(f"Sample matches:")
                for comp in matching_components[:5]:  # Show first 5
                    logger.info(f"     - {comp['name']} v{comp['version']}")
            
            return {
                "status": "success",
                "pattern": pattern,
                "total_matches": len(matching_components),
                "matching_components": matching_components,
                "sample_matches": matching_components[:10]  # Return top 10
            }
            
        except Exception as e:
            logger.error(f"Pattern search failed: {e}")
            return {"status": "error", "message": str(e)}