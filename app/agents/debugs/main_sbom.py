import logging
import json
import os
from datetime import datetime

from tools.excel_process.excel_processor import ExcelProcessor
from agents.agent_sbom import SBOMAnalysisAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("main")

def save_results(results: dict, output_path: str) -> None:
    """Save analysis results"""
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results saved to {output_path}")
        
    except Exception as e:
        logger.error(f"Failed to save results: {e}")

def main():
    """Main vulnerability analysis workflow using SBOM agent with tools"""
    
    logger.info("="*80)
    logger.info("STARTING AGENT-BASED SBOM ANALYSIS")
    logger.info("="*80)
    
    try:
        # Step 1: Process Excel file
        logger.info("Step 1: Processing Excel file")
        excel_processor = ExcelProcessor("tools/configs/excel_config.json")
        excel_result = excel_processor.process_excel("data/CB.xlsx")
        
        if not excel_result.get("success"):
            logger.error(f"Excel processing failed: {excel_result.get('error')}")
            return
        
        vulnerabilities = excel_result["data"].get("vulnerabilities", [])
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities in Excel file")
        
        if not vulnerabilities:
            logger.warning("No vulnerabilities found in Excel file")
            return
        
        # Step 2: Initialize SBOM Analysis Agent
        logger.info("Step 2: Initializing SBOM Analysis Agent")
        sbom_agent = SBOMAnalysisAgent("llama3.1:8b")
        
        # Step 3: Setup SBOM file
        sbom_filepath = "data/sbom.spdx.json"  # Update this path to your SBOM file
        logger.info(f"Step 3: Setting up SBOM file: {sbom_filepath}")
        
        setup_success = sbom_agent.setup_sbom(sbom_filepath)
        if not setup_success:
            logger.error("SBOM setup failed")
            return
        
        # Get SBOM stats
        sbom_stats = sbom_agent.get_sbom_stats()
        logger.info(f"SBOM loaded successfully: {sbom_stats}")
        
        # Test SBOM connection
        connection_test = sbom_agent.test_sbom_connection()
        logger.info(f"SBOM connection test: {connection_test}")
        
        # Step 4: Analyze vulnerabilities using SBOM agent
        logger.info("Step 4: Starting agent-based SBOM vulnerability analysis")
        
        all_results = []
        
        for i, vulnerability in enumerate(vulnerabilities, 1):
            cve_id = vulnerability.get('cve_id', 'Unknown')
            component_name = vulnerability.get('component_name', 'Unknown')
            component_version = vulnerability.get('component_version', None)
            
            logger.info(f"Analyzing vulnerability {i}/{len(vulnerabilities)}: {cve_id}")
            
            try:
                # Let the SBOM agent handle the analysis
                result = sbom_agent.analyze_vulnerability(cve_id, component_name, component_version)
                
                # Add SBOM info to result
                result["sbom_filepath"] = sbom_filepath
                result["sbom_stats"] = sbom_stats
                
                all_results.append(result)
                
                # Save individual results
                safe_cve_id = cve_id.replace('/', '_').replace('\\', '_')
                output_path = f"output/sbom_analysis_{safe_cve_id}.json"
                save_results(result, output_path)
                
                # Print summary
                print_analysis_summary(result)
                
                logger.info(f"✅ Completed SBOM analysis for {cve_id}")
                
            except Exception as e:
                logger.error(f"❌ Failed to analyze {cve_id}: {e}")
                error_result = {
                    "cve_id": cve_id,
                    "component_name": component_name,
                    "component_version": component_version,
                    "status": "failed",
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                }
                all_results.append(error_result)
                continue
        
        # Save batch summary
        if all_results:
            batch_summary = {
                "total_vulnerabilities": len(vulnerabilities),
                "successfully_analyzed": len([r for r in all_results if r.get('status') == 'completed']),
                "failed_analyses": len([r for r in all_results if r.get('status') == 'failed']),
                "analysis_method": "sbom_agent_with_tools",
                "sbom_filepath": sbom_filepath,
                "sbom_stats": sbom_stats,
                "results": all_results,
                "timestamp": datetime.now().isoformat()
            }
            
            batch_output = "output/sbom_batch_analysis.json"
            save_results(batch_summary, batch_output)
            
            print_batch_summary(batch_summary)
        
        logger.info("✅ Agent-based SBOM analysis workflow completed")
        
    except Exception as e:
        logger.error(f"❌ SBOM analysis workflow failed: {e}")
        raise

def print_analysis_summary(result: dict) -> None:
    """Print SBOM analysis summary"""
    
    print("\n" + "="*80)
    print("SBOM AGENT ANALYSIS RESULTS")
    print("="*80)
    
    print(f"CVE ID: {result.get('cve_id', 'N/A')}")
    print(f"Component: {result.get('component_name', 'N/A')}")
    print(f"Component Version: {result.get('component_version', 'N/A')}")
    print(f"Status: {result.get('status', 'N/A')}")
    print(f"Analysis Method: {result.get('analysis_method', 'N/A')}")
    
    if result.get('status') == 'completed':
        print(f"\nSBOM Agent Analysis:")
        agent_analysis = result.get('agent_analysis', 'No analysis available')
        # Print first 1000 characters
        print(agent_analysis[:1000])
        if len(agent_analysis) > 1000:
            print("\n... [Analysis truncated - see JSON file for full results]")
    
    elif result.get('status') == 'failed':
        print(f"\nError: {result.get('error', 'Unknown error')}")
    
    # Show SBOM info
    sbom_stats = result.get('sbom_stats', {})
    if sbom_stats:
        print(f"\nSBOM Information:")
        print(f"- Status: {sbom_stats.get('status', 'N/A')}")
        print(f"- Total components: {sbom_stats.get('total_components', 'N/A')}")
        print(f"- Unique components: {sbom_stats.get('unique_components', 'N/A')}")
        print(f"- Package managers: {sbom_stats.get('package_managers', 'N/A')}")
    
    print("="*80)

def print_batch_summary(batch_summary: dict) -> None:
    """Print batch SBOM analysis summary"""
    
    print("\n" + "="*100)
    print("BATCH SBOM ANALYSIS SUMMARY")
    print("="*100)
    
    print(f"Total vulnerabilities: {batch_summary.get('total_vulnerabilities', 0)}")
    print(f"Successfully analyzed: {batch_summary.get('successfully_analyzed', 0)}")
    print(f"Failed analyses: {batch_summary.get('failed_analyses', 0)}")
    print(f"Analysis method: {batch_summary.get('analysis_method', 'N/A')}")
    
    sbom_stats = batch_summary.get('sbom_stats', {})
    print(f"\nSBOM File: {batch_summary.get('sbom_filepath', 'N/A')}")
    print(f"SBOM status: {sbom_stats.get('status', 'N/A')}")
    print(f"SBOM components: {sbom_stats.get('total_components', 'N/A')}")
    print(f"Unique components: {sbom_stats.get('unique_components', 'N/A')}")
    
    print(f"\nResults saved to: output/sbom_batch_analysis.json")
    print("="*100)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("SBOM analysis interrupted by user")
    except Exception as e:
        logger.error(f"SBOM analysis failed: {e}")
    finally:
        logger.info("Cleanup completed")