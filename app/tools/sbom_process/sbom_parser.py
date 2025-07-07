import logging
from typing import Dict, List, Optional
from pathlib import Path

# Correct SPDX Tools v0.8 imports
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.model import Document, Package, File as SpdxFile
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

logger = logging.getLogger("sbom_parser")

class SBOMParser:
    """Parser for SPDX SBOM files using official SPDX tools v0.8+"""
    
    def __init__(self):
        self.document: Optional[Document] = None
        
    def parse_file(self, filepath: str) -> Dict:
        """Parse SPDX SBOM file using official SPDX tools"""
        try:
            logger.info(f"Parsing SBOM file: {filepath}")
            
            # Parse using SPDX tools v0.8
            self.document = parse_file(filepath)
            
            if not self.document:
                logger.error(f"Failed to parse SBOM file: {filepath}")
                return self._empty_sbom()
            
            # Validate the document
            try:
                validation_messages = validate_full_spdx_document(self.document)
                if validation_messages:
                    logger.warning(f"SBOM validation warnings: {len(validation_messages)} issues found")
                    for msg in validation_messages[:5]:  # Log first 5 warnings
                        logger.warning(f"Validation: {msg.validation_message}")
                else:
                    logger.info("SBOM validation passed successfully")
            except Exception as validation_error:
                logger.warning(f"Could not validate SBOM: {validation_error}")
            
            # Convert to our standard format
            sbom_info = self._convert_to_standard_format()
            
            logger.info(f"Successfully parsed SBOM: {len(sbom_info.get('components', []))} components found")
            return sbom_info
            
        except Exception as e:
            logger.error(f"Error parsing SBOM file {filepath}: {e}")
            return self._empty_sbom()
    
    def _convert_to_standard_format(self) -> Dict:
        """Convert SPDX Document to our standard format"""
        try:
            if not self.document:
                return self._empty_sbom()
            
            # Extract document metadata (v0.8 structure)
            sbom_info = {
                'format': 'SPDX-v0.8',
                'version': str(self.document.creation_info.spdx_version) if self.document.creation_info else 'Unknown',
                'name': self.document.creation_info.name if self.document.creation_info else 'Unknown',
                'spdx_id': self.document.creation_info.spdx_id if self.document.creation_info else 'SPDXRef-DOCUMENT',
                'namespace': self.document.creation_info.document_namespace if self.document.creation_info else 'Unknown',
                'created': str(self.document.creation_info.created) if self.document.creation_info else 'Unknown',
                'creators': self._extract_creators(),
                'components': [],
                'relationships': []
            }
            
            # Extract packages (components)
            if hasattr(self.document, 'packages') and self.document.packages:
                logger.info(f"Processing {len(self.document.packages)} packages")
                for package in self.document.packages:
                    component = self._convert_package_to_component(package)
                    sbom_info['components'].append(component)
            
            # Extract relationships
            if hasattr(self.document, 'relationships') and self.document.relationships:
                logger.info(f"Processing {len(self.document.relationships)} relationships")
                for relationship in self.document.relationships:
                    rel_info = {
                        'source': relationship.spdx_element_id,
                        'target': relationship.related_spdx_element_id,
                        'type': str(relationship.relationship_type)
                    }
                    sbom_info['relationships'].append(rel_info)
            
            # Extract files as components if no packages exist
            if not sbom_info['components'] and hasattr(self.document, 'files') and self.document.files:
                logger.info(f"No packages found, extracting {len(self.document.files)} files as components")
                for file_obj in self.document.files:
                    component = self._convert_file_to_component(file_obj)
                    sbom_info['components'].append(component)
            
            logger.info(f"Converted SPDX document: {len(sbom_info['components'])} components, {len(sbom_info['relationships'])} relationships")
            return sbom_info
            
        except Exception as e:
            logger.error(f"Error converting SPDX document to standard format: {e}")
            return self._empty_sbom()
    
    def _convert_package_to_component(self, package: Package) -> Dict:
        """Convert SPDX Package to our component format"""
        try:
            # Safe license handling
            def safe_license_string(license_obj):
                if license_obj is None:
                    return 'Unknown'
                try:
                    return str(license_obj)
                except Exception:
                    return 'Complex License Expression'
            
            component = {
                'spdx_id': package.spdx_id if hasattr(package, 'spdx_id') else 'Unknown',
                'name': package.name if hasattr(package, 'name') else 'Unknown',
                'version': package.version if hasattr(package, 'version') else 'Unknown',
                'supplier': str(package.supplier) if hasattr(package, 'supplier') and package.supplier else 'Unknown',
                'originator': str(package.originator) if hasattr(package, 'originator') and package.originator else 'Unknown',
                'download_location': package.download_location if hasattr(package, 'download_location') else 'Unknown',
                'homepage': package.homepage if hasattr(package, 'homepage') else '',
                'license': safe_license_string(package.license_concluded) if hasattr(package, 'license_concluded') else 'Unknown',
                'license_declared': safe_license_string(package.license_declared) if hasattr(package, 'license_declared') else 'Unknown',
                'copyright': package.copyright_text if hasattr(package, 'copyright_text') else '',
                'summary': package.summary if hasattr(package, 'summary') else '',
                'description': package.description if hasattr(package, 'description') else '',
                'external_refs': self._extract_external_refs(package),
                'purl': self._extract_purl_from_package(package),
                'cpe': self._extract_cpe_from_package(package),
                'checksums': self._extract_checksums(package),
                'verification_code': self._extract_verification_code(package),
                'files_analyzed': package.files_analyzed if hasattr(package, 'files_analyzed') else False,
                'type': 'package'
            }
            
            return component
            
        except Exception as e:
            logger.error(f"Error converting package to component: {e}")
            return {
                'name': 'Error parsing package',
                'version': 'Unknown',
                'type': 'package',
                'error': str(e)
            }
    
    def _convert_file_to_component(self, file_obj: SpdxFile) -> Dict:
        """Convert SPDX File to our component format"""
        try:
            # Safe license handling
            def safe_license_string(license_obj):
                if license_obj is None:
                    return 'Unknown'
                try:
                    return str(license_obj)
                except Exception:
                    return 'Complex License Expression'
            
            component = {
                'spdx_id': file_obj.spdx_id if hasattr(file_obj, 'spdx_id') else 'Unknown',
                'name': file_obj.name if hasattr(file_obj, 'name') else 'Unknown',
                'version': 'Unknown',  # Files don't typically have versions
                'type': 'file',
                'license': safe_license_string(file_obj.license_concluded) if hasattr(file_obj, 'license_concluded') else 'Unknown',
                'copyright': file_obj.copyright_text if hasattr(file_obj, 'copyright_text') else '',
                'checksums': self._extract_checksums(file_obj),
                'comment': file_obj.comment if hasattr(file_obj, 'comment') else '',
                'file_types': [str(ft) for ft in file_obj.file_types] if hasattr(file_obj, 'file_types') else []
            }
            
            return component
            
        except Exception as e:
            logger.error(f"Error converting file to component: {e}")
            return {
                'name': 'Error parsing file',
                'version': 'Unknown',
                'type': 'file',
                'error': str(e)
            }
    
    def _extract_creators(self) -> List[str]:
        """Extract creators from creation info"""
        try:
            if not hasattr(self.document, 'creation_info') or not self.document.creation_info:
                return []
            
            creators = []
            if hasattr(self.document.creation_info, 'creators') and self.document.creation_info.creators:
                for creator in self.document.creation_info.creators:
                    creators.append(str(creator))
            
            return creators
            
        except Exception as e:
            logger.error(f"Error extracting creators: {e}")
            return []
    
    def _extract_external_refs(self, package: Package) -> List[Dict]:
        """Extract external references from package"""
        try:
            external_refs = []
            
            if hasattr(package, 'external_package_refs') and package.external_package_refs:
                for ref in package.external_package_refs:
                    ref_info = {
                        'category': str(ref.category) if hasattr(ref, 'category') else 'Unknown',
                        'type': str(ref.reference_type) if hasattr(ref, 'reference_type') else 'Unknown',
                        'locator': ref.locator if hasattr(ref, 'locator') else 'Unknown',
                        'comment': ref.comment if hasattr(ref, 'comment') else ''
                    }
                    external_refs.append(ref_info)
            
            return external_refs
            
        except Exception as e:
            logger.error(f"Error extracting external references: {e}")
            return []
    
    def _extract_purl_from_package(self, package: Package) -> str:
        """Extract Package URL from external references"""
        try:
            if hasattr(package, 'external_package_refs') and package.external_package_refs:
                for ref in package.external_package_refs:
                    if hasattr(ref, 'reference_type') and 'purl' in str(ref.reference_type).lower():
                        return ref.locator if hasattr(ref, 'locator') else ''
            return ''
            
        except Exception as e:
            logger.error(f"Error extracting PURL: {e}")
            return ''
    
    def _extract_cpe_from_package(self, package: Package) -> str:
        """Extract CPE from external references"""
        try:
            if hasattr(package, 'external_package_refs') and package.external_package_refs:
                for ref in package.external_package_refs:
                    if hasattr(ref, 'reference_type') and 'cpe' in str(ref.reference_type).lower():
                        return ref.locator if hasattr(ref, 'locator') else ''
            return ''
            
        except Exception as e:
            logger.error(f"Error extracting CPE: {e}")
            return ''
    
    def _extract_checksums(self, obj) -> List[Dict]:
        """Extract checksums from package or file"""
        try:
            checksums = []
            
            if hasattr(obj, 'checksums') and obj.checksums:
                for checksum in obj.checksums:
                    checksum_info = {
                        'algorithm': str(checksum.algorithm) if hasattr(checksum, 'algorithm') else 'Unknown',
                        'value': checksum.value if hasattr(checksum, 'value') else 'Unknown'
                    }
                    checksums.append(checksum_info)
            
            return checksums
            
        except Exception as e:
            logger.error(f"Error extracting checksums: {e}")
            return []
    
    def _extract_verification_code(self, package: Package) -> Dict:
        """Extract package verification code"""
        try:
            if hasattr(package, 'package_verification_code') and package.package_verification_code:
                return {
                    'value': package.package_verification_code.value if hasattr(package.package_verification_code, 'value') else 'Unknown',
                    'excluded_files': list(package.package_verification_code.excluded_files) if hasattr(package.package_verification_code, 'excluded_files') else []
                }
            return {}
            
        except Exception as e:
            logger.error(f"Error extracting verification code: {e}")
            return {}
    
    def _empty_sbom(self) -> Dict:
        """Return empty SBOM structure"""
        return {
            'format': 'Unknown',
            'version': 'Unknown',
            'name': 'Unknown',
            'spdx_id': 'Unknown',
            'namespace': 'Unknown',
            'created': 'Unknown',
            'creators': [],
            'components': [],
            'relationships': []
        }
    
    def find_component_by_name(self, sbom_data: Dict, component_name: str) -> List[Dict]:
        """Find components matching a given name (fuzzy matching)"""
        matches = []
        component_name_lower = str(component_name).lower()  # Convert to string first
        
        for component in sbom_data.get('components', []):
            comp_name = str(component.get('name', '')).lower()  # Convert to string first
            
            # Skip if component name is empty
            if not comp_name:
                continue
            
            # Exact match
            if comp_name == component_name_lower:
                matches.append(component)
                continue
            
            # Partial match
            if component_name_lower in comp_name or comp_name in component_name_lower:
                matches.append(component)
                continue
            
            # Check PURL for name matching
            purl = str(component.get('purl', '')).lower()
            if purl and component_name_lower in purl:
                matches.append(component)
                continue
            
            # Check external references for name matching
            for ext_ref in component.get('external_refs', []):
                locator = str(ext_ref.get('locator', '')).lower()
                if locator and component_name_lower in locator:
                    matches.append(component)
                    break
        
        return matches
    
    def find_component_by_version(self, sbom_data: Dict, component_name: str, version: str) -> List[Dict]:
        """Find components matching name and version"""
        name_matches = self.find_component_by_name(sbom_data, component_name)
        version_matches = []
        
        version_lower = str(version).lower()  # Convert to string first
        
        for component in name_matches:
            comp_version = str(component.get('version', '')).lower()  # Convert to string first
            
            # Skip if version is empty
            if not comp_version:
                continue
            
            # Exact version match
            if comp_version == version_lower:
                version_matches.append(component)
                continue
            
            # Partial version match
            if version_lower in comp_version or comp_version in version_lower:
                version_matches.append(component)
                continue
            
            # Check PURL for version matching
            purl = str(component.get('purl', '')).lower()
            if purl and version_lower in purl:
                version_matches.append(component)
        
        return version_matches
    
    def find_components_by_type(self, sbom_data: Dict, component_type: str) -> List[Dict]:
        """Find components by type (e.g., 'library', 'application', 'file')"""
        matches = []
        
        for component in sbom_data.get('components', []):
            comp_type = component.get('type', '').lower()
            if comp_type == component_type.lower():
                matches.append(component)
        
        return matches
    
    def get_component_dependencies(self, sbom_data: Dict, component_spdx_id: str) -> List[Dict]:
        """Get dependencies for a specific component using relationships"""
        dependencies = []
        
        for relationship in sbom_data.get('relationships', []):
            if (relationship.get('source') == component_spdx_id and 
                'depends' in relationship.get('type', '').lower()):
                
                # Find the target component
                target_id = relationship.get('target')
                for component in sbom_data.get('components', []):
                    if component.get('spdx_id') == target_id:
                        dependencies.append(component)
                        break
        
        return dependencies
    
    def get_statistics(self, sbom_data: Dict) -> Dict:
        """Get statistics about the SBOM"""
        components = sbom_data.get('components', [])
        relationships = sbom_data.get('relationships', [])
        
        # Count components by type
        type_counts = {}
        license_counts = {}
        
        for component in components:
            comp_type = component.get('type', 'package')
            type_counts[comp_type] = type_counts.get(comp_type, 0) + 1
            
            license_info = component.get('license', 'Unknown')
            license_counts[license_info] = license_counts.get(license_info, 0) + 1
        
        # Count relationships by type
        rel_type_counts = {}
        for relationship in relationships:
            rel_type = relationship.get('type', 'Unknown')
            rel_type_counts[rel_type] = rel_type_counts.get(rel_type, 0) + 1
        
        return {
            'total_components': len(components),
            'total_relationships': len(relationships),
            'component_types': type_counts,
            'license_distribution': license_counts,
            'relationship_types': rel_type_counts,
            'format': sbom_data.get('format', 'Unknown'),
            'spdx_version': sbom_data.get('version', 'Unknown')
        }