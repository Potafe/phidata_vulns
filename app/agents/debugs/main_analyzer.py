import logging
import json
import os
from datetime import datetime

from tools.excel_process.excel_processor import ExcelProcessor
from agents.agent_vuln_analyzer import VulnerabilityAnalyzerAgent

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
    """Main vulnerability analysis workflow using VulnerabilityAnalyzerAgent"""
    
    logger.info("="*80)
    logger.info("STARTING COMPREHENSIVE VULNERABILITY ANALYSIS")
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
        
        # Step 2: Initialize Vulnerability Analyzer Agent
        logger.info("Step 2: Initializing Vulnerability Analyzer Agent")
        vuln_agent = VulnerabilityAnalyzerAgent("llama3.1:8b")
        
        # Step 3: Test database connection
        logger.info("Step 3: Testing database connection")
        connection_test = vuln_agent.test_database_connection()
        logger.info(f"Database connection test: {connection_test}")
        
        if not connection_test.get("database_accessible", False):
            logger.warning("Database not accessible - analysis will rely on web search only")
        
        # Step 4: Analyze vulnerabilities using the agent
        logger.info("Step 4: Starting comprehensive vulnerability analysis")
        
        all_results = []
        
        for i, vulnerability in enumerate(vulnerabilities, 1):
            cve_id = vulnerability.get('cve_id', 'Unknown')
            component_name = vulnerability.get('component_name', 'Unknown')
            component_version = vulnerability.get('component_version', None)
            vendor = vulnerability.get('vendor', None)
            product = vulnerability.get('product', None)
            
            logger.info(f"Analyzing vulnerability {i}/{len(vulnerabilities)}: {cve_id}")
            
            try:
                # Let the vulnerability analyzer agent handle the comprehensive analysis
                result = vuln_agent.analyze_vulnerability(
                    cve_id=cve_id,
                    component_name=component_name,
                    component_version=component_version,
                    vendor=vendor,
                    product=product
                )
                
                # Add database connection info to result
                result["database_connection"] = connection_test
                
                all_results.append(result)
                
                # Save individual results
                safe_cve_id = cve_id.replace('/', '_').replace('\\', '_')
                output_path = f"output/vuln_analysis_{safe_cve_id}.json"
                save_results(result, output_path)
                
                # Print summary
                print_analysis_summary(result)
                
                logger.info(f"✅ Completed vulnerability analysis for {cve_id}")
                
            except Exception as e:
                logger.error(f"❌ Failed to analyze {cve_id}: {e}")
                error_result = {
                    "cve_id": cve_id,
                    "component_name": component_name,
                    "component_version": component_version,
                    "vendor": vendor,
                    "product": product,
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
                "analysis_method": "comprehensive_vulnerability_analysis_with_conditions",
                "data_sources": ["CISA_KEV", "EPSS", "web_search", "security_news", "technical_research"],
                "database_connection": connection_test,
                "results": all_results,
                "timestamp": datetime.now().isoformat()
            }
            
            batch_output = "output/vuln_batch_analysis.json"
            save_results(batch_summary, batch_output)
            
            print_batch_summary(batch_summary)
        
        logger.info("✅ Comprehensive vulnerability analysis workflow completed")
        
    except Exception as e:
        logger.error(f"❌ Vulnerability analysis workflow failed: {e}")
        raise

def print_analysis_summary(result: dict) -> None:
    """Print vulnerability analysis summary"""
    
    print("\n" + "="*80)
    print("VULNERABILITY ANALYSIS RESULTS")
    print("="*80)
    
    print(f"CVE ID: {result.get('cve_id', 'N/A')}")
    print(f"Component: {result.get('component_name', 'N/A')}")
    print(f"Component Version: {result.get('component_version', 'N/A')}")
    print(f"Vendor: {result.get('vendor', 'N/A')}")
    print(f"Product: {result.get('product', 'N/A')}")
    print(f"Status: {result.get('status', 'N/A')}")
    print(f"Analysis Method: {result.get('analysis_method', 'N/A')}")
    
    if result.get('status') == 'completed':
        print(f"\nVulnerability Analysis:")
        vuln_analysis = result.get('vulnerability_analysis', 'No analysis available')
        # Print first 1500 characters to show more details
        print(vuln_analysis[:1500])
        if len(vuln_analysis) > 1500:
            print("\n... [Analysis truncated - see JSON file for full results]")
    
    elif result.get('status') == 'failed':
        print(f"\nError: {result.get('error', 'Unknown error')}")
    
    # Show data sources
    data_sources = result.get('data_sources', [])
    if data_sources:
        print(f"\nData Sources: {', '.join(data_sources)}")
    
    # Show database connection status
    db_connection = result.get('database_connection', {})
    if db_connection:
        print(f"Database Accessible: {db_connection.get('database_accessible', 'Unknown')}")
    
    print("="*80)

def print_batch_summary(batch_summary: dict) -> None:
    """Print batch vulnerability analysis summary"""
    
    print("\n" + "="*100)
    print("BATCH VULNERABILITY ANALYSIS SUMMARY")
    print("="*100)
    
    print(f"Total vulnerabilities: {batch_summary.get('total_vulnerabilities', 0)}")
    print(f"Successfully analyzed: {batch_summary.get('successfully_analyzed', 0)}")
    print(f"Failed analyses: {batch_summary.get('failed_analyses', 0)}")
    print(f"Analysis method: {batch_summary.get('analysis_method', 'N/A')}")
    
    # Show data sources
    data_sources = batch_summary.get('data_sources', [])
    print(f"Data sources: {', '.join(data_sources)}")
    
    # Show database connection status
    db_connection = batch_summary.get('database_connection', {})
    print(f"Database connection: {db_connection.get('status', 'Unknown')}")
    print(f"Database accessible: {db_connection.get('database_accessible', 'Unknown')}")
    
    # Calculate success rate
    total = batch_summary.get('total_vulnerabilities', 0)
    successful = batch_summary.get('successfully_analyzed', 0)
    if total > 0:
        success_rate = (successful / total) * 100
        print(f"Success rate: {success_rate:.1f}%")
    
    print(f"\nResults saved to: output/vuln_batch_analysis.json")
    print("Individual results saved to: output/vuln_analysis_<CVE_ID>.json")
    print("="*100)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Vulnerability analysis interrupted by user")
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {e}")
    finally:
        logger.info("Cleanup completed")