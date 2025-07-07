import logging
from datetime import datetime
from typing import Dict, List, Optional

from phi.agent import Agent
from phi.model.ollama import Ollama
from phi.tools.duckduckgo import DuckDuckGo
from phi.tools.newspaper4k import Newspaper4k

from tools.db_process.vuln_db_tools import VulnerabilityDBTools

logger = logging.getLogger(__name__)

class VulnerabilityAnalyzerAgent:
    """Comprehensive vulnerability analysis agent using web search and database tools"""
    
    def __init__(self, model_id: str = "llama3.1:8b"):
        self.model = Ollama(id=model_id)
        
        # Initialize tools
        self.db_tools = VulnerabilityDBTools()
        self.web_search = DuckDuckGo()
        self.news_reader = Newspaper4k()
        
        # Create agent with comprehensive tool integration
        self.agent = Agent(
            name="VulnerabilityAnalyzerAgent",
            role="Comprehensive vulnerability intelligence analyst",
            model=self.model,
            tools=[self.db_tools, self.web_search, self.news_reader],
            instructions=[
                "You are a vulnerability intelligence analyst specializing in comprehensive CVE analysis.",
                "Your job is to gather complete information about vulnerabilities from multiple sources.",
                "",
                "CRITICAL REQUIREMENTS:",
                "- You MUST use ONLY the actual tool results in your analysis",
                "- NEVER fabricate, simulate, or hallucinate tool outputs",
                "- Quote tool results EXACTLY as returned",
                "- If tools return no data, report that honestly",
                "",
                "WORKFLOW:",
                "1. Call search_kev_database(cve_id) and report the EXACT result",
                "2. Call get_epss_score(cve_id) and report the EXACT result", 
                "3. Search the web for vulnerability details, attack vectors, and exploitation conditions",
                "4. Search for proof-of-concept code, patches, and mitigation strategies",
                "5. Read relevant security articles and advisories",
                "6. Provide comprehensive analysis with detailed vulnerability conditions",
                "",
                "REPORTING FORMAT:",
                "## Tool Results (EXACT QUOTES)",
                "**KEV Database:** [exact quote from tool]",
                "**EPSS Score:** [exact quote from tool]",
                "**Web Search Results:** [exact quotes from web search]",
                "",
                "## Vulnerability Details",
                "**CVE Description:** [based on web research]",
                "**Attack Vector:** [how the vulnerability can be exploited]",
                "**Affected Components:** [specific components/classes/methods]",
                "",
                "## Vulnerability Conditions",
                "List the specific conditions that make this CVE exploitable:",
                "1. [Condition 1 with code example if found]",
                "2. [Condition 2 with risk level]",
                "3. [Condition 3 with exploitation scenario]",
                "",
                "## Risk Assessment (Based on Real Data)",
                "[analyze KEV status, EPSS score, and web intelligence]",
                "",
                "## Remediation",
                "**Patches:** [available patches and versions]",
                "**Mitigation:** [temporary workarounds]",
                "**Recommendations:** [prioritization guidance]",
                "",
                "FORBIDDEN:",
                "- Making up CVE numbers",
                "- Fabricating KEV status",
                "- Creating fake EPSS scores",
                "- Inventing vulnerability details not found in tool results"
            ],
            show_tool_calls=True,
            markdown=True,
            debug_mode=True
        )
    
    def analyze_vulnerability(self, cve_id: str, component_name: str, component_version: str = None, 
                            vendor: str = None, product: str = None) -> dict:
        """Perform comprehensive vulnerability analysis"""
        
        try:
            # Create comprehensive analysis prompt
            analysis_prompt = f"""
            Perform a comprehensive vulnerability analysis for {cve_id}.
            
            Component Information:
            - CVE ID: {cve_id}
            - Component: {component_name}
            - Version: {component_version}
            - Vendor: {vendor}
            - Product: {product}
            
            CRITICAL: You MUST report ONLY the actual tool results. Do NOT fabricate any data.
            
            Required Analysis Steps:
            
            Step 1: Database Analysis
            - Call search_kev_database("{cve_id}") and quote the EXACT result
            - Call get_epss_score("{cve_id}") and quote the EXACT result
            
            Step 2: Vulnerability Research
            - Search for "{cve_id} vulnerability details attack vector exploitation conditions"
            - Search for "{cve_id} {component_name} affected methods classes functions"
            - Search for "{cve_id} proof of concept exploit code examples"
            - Search for "{cve_id} patch fix mitigation workaround"
            
            Step 3: Technical Details
            Based on your web research findings, identify:
            - What specific conditions make this CVE exploitable
            - Which methods/classes/functions are affected
            - How an attacker would exploit this vulnerability
            - What code patterns are vulnerable vs safe
            
            Format your response exactly as:
            
            ## Tool Results (EXACT QUOTES)
            **KEV Database Result:** [paste exact search_kev_database output]
            **EPSS Score Result:** [paste exact get_epss_score output]
            **Web Search Results:** [summarize key findings from web search]
            
            ## Vulnerability Details
            **CVE Description:** [based on research]
            **Attack Vector:** [how it's exploited]
            **Affected Components:** [specific technical details]
            **Root Cause:** [underlying security issue]
            
            ## Vulnerability Conditions
            {cve_id} is vulnerable when the following conditions are met:
            
            1. [First exploitable condition with technical details]
            2. [Second condition with risk assessment]
            3. [Third condition with code examples if found]
            4. [Additional conditions as discovered]
            
            ## Risk Assessment (Based on Real Data)
            **KEV Status:** [from actual tool result]
            **EPSS Score:** [from actual tool result] 
            **Exploitation Likelihood:** [based on research]
            **Impact:** [potential damage]
            **Priority:** [urgency recommendation]
            
            ## Remediation
            **Available Patches:** [versions that fix the issue]
            **Mitigation Strategies:** [temporary workarounds]
            **Recommendations:** [specific actions to take]
            
            Start now - call the database tools first, then perform comprehensive web research.
            """
            
            logger.info(f"🔍 Starting comprehensive vulnerability analysis for {cve_id}")
            
            # Run the agent
            result = self.agent.run(analysis_prompt)
            
            if result:
                logger.info(f"✅ Vulnerability analysis completed for {cve_id}")
                return {
                    "cve_id": cve_id,
                    "component_name": component_name,
                    "component_version": component_version,
                    "vendor": vendor,
                    "product": product,
                    "status": "completed",
                    "vulnerability_analysis": str(result.content),
                    "timestamp": datetime.now().isoformat(),
                    "analysis_method": "comprehensive_vulnerability_analysis_with_conditions",
                    "data_sources": ["CISA_KEV", "EPSS", "web_search", "security_news", "technical_research"]
                }
            else:
                logger.warning(f"⚠️ No result returned for {cve_id}")
                return {
                    "cve_id": cve_id,
                    "component_name": component_name,
                    "status": "failed",
                    "error": "No result returned from vulnerability analyzer",
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"❌ Vulnerability analysis failed: {e}")
            return {
                "cve_id": cve_id,
                "component_name": component_name,
                "status": "failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def test_database_connection(self) -> dict:
        """Test database connectivity"""
        try:
            # Test the database connection
            test_result = self.db_tools.test_connection()
            
            return {
                "status": "success" if test_result else "failed",
                "database_accessible": test_result,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "database_accessible": False,
                "timestamp": datetime.now().isoformat()
            }