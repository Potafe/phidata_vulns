import logging
from datetime import datetime

from phi.agent import Agent
from phi.model.ollama import Ollama

from tools.sbom_process.sbom_tools import SBOMTools

logger = logging.getLogger(__name__)

class SBOMAnalysisAgent:
    """SBOM analysis agent that relies entirely on SBOM tool calls"""
    
    def __init__(self, model_id: str = "llama3.1:8b"):
        self.model = Ollama(id=model_id)
        
        # Initialize SBOM tools
        self.sbom_tools = SBOMTools()
        
        # Create agent with proper tool integration
        self.agent = Agent(
            name="SBOMAnalysisAgent",
            role="SBOM vulnerability analysis expert",
            model=self.model,
            tools=[self.sbom_tools],
            instructions=[
                "You are an SBOM analysis specialist focused on software bill of materials vulnerability analysis.",
                "Your job is to search SBOM files for specific vulnerable components and assess risk.",
                "",
                "WORKFLOW:",
                "1. When asked to analyze a CVE, you MUST call analyze_sbom(component_name, component_version)",
                "2. Report the exact tool response",
                "3. Provide analysis based on the actual tool results",
                "",
                "IMPORTANT:",
                "- Always call the analyze_sbom tool with the component name and version",
                "- Report exactly what the tool returns about component presence",
                "- Base your vulnerability analysis only on real SBOM search results",
                "- If components are not found, report that honestly",
                "- Assess risk based on actual component versions found in SBOM"
            ],
            show_tool_calls=True,
            markdown=True,
            debug_mode=True
        )
    
    def setup_sbom(self, sbom_filepath: str) -> bool:
        """Setup SBOM for analysis"""
        try:
            from tools.sbom_process.sbom_parser import SBOMParser
            
            logger.info(f"Loading SBOM file: {sbom_filepath}")
            
            # Parse SBOM file
            sbom_parser = SBOMParser()
            sbom_data = sbom_parser.parse_file(sbom_filepath)
            
            if not sbom_data or not sbom_data.get('components'):
                logger.error(f"Failed to parse SBOM or no components found")
                return False
            
            # Set SBOM data in tools
            self.sbom_tools.set_sbom_data(sbom_data)
            
            logger.info(f"✅ SBOM loaded successfully: {len(sbom_data.get('components', []))} components")
            return True
            
        except Exception as e:
            logger.error(f"❌ SBOM setup failed: {e}")
            return False
    
    def analyze_vulnerability(self, cve_id: str, component_name: str, component_version: str = None) -> dict:
        """Analyze vulnerability using agent with SBOM tools"""
        
        try:
            analysis_prompt = f"""
            Analyze the SBOM for vulnerability {cve_id} in component {component_name}.
            
            You MUST call analyze_sbom("{component_name}", "{component_version}") to search the SBOM.
            
            After calling the tool, provide a comprehensive analysis that includes:
            1. The exact tool results about component presence
            2. Whether the vulnerable component was found in the SBOM
            3. Version comparison and vulnerability assessment
            4. Risk level and recommendations
            5. Impact assessment based on SBOM findings
            
            Component Details:
            - CVE ID: {cve_id}
            - Component Name: {component_name}
            - Vulnerable Version: {component_version}
            
            Call the analyze_sbom tool now.
            """
            
            logger.info(f"🤖 Starting SBOM agent analysis for {cve_id}")
            
            # Run the agent
            result = self.agent.run(analysis_prompt)
            
            if result:
                logger.info(f"✅ SBOM agent analysis completed for {cve_id}")
                return {
                    "cve_id": cve_id,
                    "component_name": component_name,
                    "component_version": component_version,
                    "status": "completed",
                    "agent_analysis": str(result.content),
                    "timestamp": datetime.now().isoformat(),
                    "analysis_method": "sbom_agent_with_tools"
                }
            else:
                logger.warning(f"⚠️ No result returned for {cve_id}")
                return {
                    "cve_id": cve_id,
                    "component_name": component_name,
                    "component_version": component_version,
                    "status": "failed",
                    "error": "No result returned from SBOM agent",
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"❌ SBOM agent analysis failed: {e}")
            return {
                "cve_id": cve_id,
                "component_name": component_name,
                "component_version": component_version,
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def get_sbom_stats(self) -> dict:
        """Get SBOM statistics"""
        try:
            if not self.sbom_tools.sbom_loaded:
                return {"status": "not_loaded", "message": "SBOM not loaded"}
            
            return self.sbom_tools.get_sbom_statistics()
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def test_sbom_connection(self) -> dict:
        """Test if SBOM is properly loaded and accessible"""
        try:
            if not self.sbom_tools.sbom_loaded:
                return {"status": "not_loaded", "message": "SBOM not loaded"}
            
            # Get basic stats
            stats = self.sbom_tools.get_sbom_statistics()
            
            return {
                "status": "success",
                "sbom_stats": stats,
                "connection_working": True,
                "total_components": stats.get("total_components", 0)
            }
            
        except Exception as e:
            return {
                "status": "error", 
                "message": str(e),
                "connection_working": False
            }