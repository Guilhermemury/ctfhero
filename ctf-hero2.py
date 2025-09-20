#!/usr/bin/env python3
"""
CTF Recon Suite - An optimized automation framework for CTF and pentesting.
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set, Dict, Any
from contextlib import contextmanager
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from functools import lru_cache

# External dependency: rich. Install with 'pip install rich'
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import SpinnerColumn, Progress
except ImportError:
    print("Error: 'rich' library not found. Please install it using 'pip install rich'")
    sys.exit(1)

class Config:
    """Centralized configuration for the tool."""
    HOSTS_FILE = "/etc/hosts"
    DEFAULT_OUTPUT_DIR = "output"
    REQUIRED_TOOLS = ["nmap", "ffuf", "whatweb", "searchsploit", "curl"]
    WORDLISTS = {
        "dirs_medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "dirs_small": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    }
    TIMEOUTS = {
        'nmap_quick': 1200,
        'nmap_full': 3600,
        'ffuf': 300,
        'whatweb': 60,
        'curl': 10,
        'searchsploit': 30,
    }
    PERFORMANCE = {
        'max_workers': 4,  # Máximo de threads paralelas
        'ffuf_threads': 40,  # Threads para ffuf
        'nmap_timing': 4,  # Timing template do nmap (0-5)
        'connection_timeout': 5,  # Timeout de conexão em segundos
        'enable_cache': True,  # Habilitar cache de comandos
    }

class PerformanceManager:
    """Gerencia performance e cache de comandos."""
    def __init__(self):
        self.cache = {}
        self.cache_lock = threading.Lock()
        self.executor = ThreadPoolExecutor(max_workers=Config.PERFORMANCE['max_workers'])
    
    @lru_cache(maxsize=128)
    def get_cached_result(self, cmd_hash: str) -> Optional[Dict[str, Any]]:
        """Retorna resultado em cache se disponível."""
        if not Config.PERFORMANCE['enable_cache']:
            return None
        
        with self.cache_lock:
            return self.cache.get(cmd_hash)
    
    def set_cached_result(self, cmd_hash: str, result: Dict[str, Any]):
        """Armazena resultado no cache."""
        if not Config.PERFORMANCE['enable_cache']:
            return
        
        with self.cache_lock:
            self.cache[cmd_hash] = result
    
    def clear_cache(self):
        """Limpa o cache."""
        with self.cache_lock:
            self.cache.clear()
    
    def shutdown(self):
        """Encerra o executor de threads."""
        self.executor.shutdown(wait=True)

class ConsoleManager:
    """Manages all console output using the rich library."""
    def __init__(self):
        self.console = Console()

    def print_banner(self):
        """Prints the tool's banner."""
        banner = """
 [bold cyan]██████╗████████╗███████╗   ██╗  ██╗███████╗██████╗ ██████╗ [/bold cyan]
 [bold cyan]██╔════╝╚══██╔══╝██╔════╝   ██║  ██║██╔════╝██╔══██╗██╔═══██╗[/bold cyan]
 [bold cyan]██║       ██║   █████╗     ███████║█████╗  ██████╔╝██║   ██║[/bold cyan]
 [bold cyan]██║       ██║   ██╔══╝     ██╔══██║██╔══╝  ██╔══██╗██║   ██║[/bold cyan]
 [bold cyan]╚██████╗   ██║   ██║        ██║  ██║███████╗██║  ██║╚██████╔╝[/bold cyan]
 [bold cyan] ╚═════╝   ╚═╝   ╚═╝        ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ [/bold cyan]
        """
        self.console.print(banner)
        self.log_info("Optimized automation framework for CTF and pentesting.", bold=True)
        self.console.print("-" * 60)

    def log_info(self, message: str, bold: bool = False):
        self.console.print(f"[bold blue][*][/bold blue] {message}", style="bold" if bold else "")

    def log_success(self, message: str):
        self.console.print(f"[bold green][+][/bold green] {message}")

    def log_warning(self, message: str):
        self.console.print(f"[bold yellow][!][/bold yellow] {message}")

    def log_error(self, message: str):
        self.console.print(f"[bold red][✗][/bold red] {message}")

    def print_table(self, title: str, columns: List[str], rows: List[List[str]]):
        """Prints data in a structured table."""
        if not rows:
            self.log_warning(f"No data to display for '{title}'.")
            return
            
        table = Table(title=title, show_header=True, header_style="bold magenta")
        for col in columns:
            table.add_column(col)
        for row in rows:
            table.add_row(*row)
        self.console.print(table)

@contextmanager
def HostsManager(ip: str, hostnames: Set[str]):
    """
    A secure context manager for temporarily modifying /etc/hosts.
    It automatically restores the original file on exit or error.
    """
    console = ConsoleManager()
    if os.geteuid() != 0:
        console.log_warning(f"Not running as root. Cannot modify {Config.HOSTS_FILE}.")
        yield
        return

    original_content = ""
    hosts_path = Path(Config.HOSTS_FILE)
    try:
        # 1. Backup original content
        if hosts_path.exists():
            original_content = hosts_path.read_text()

        # 2. Add new entries
        with hosts_path.open("a") as f:
            f.write("\n# Added by CTF Recon Suite\n")
            for hostname in hostnames:
                entry = f"{ip}\t{hostname}\n"
                f.write(entry)
                console.log_success(f"Added to {Config.HOSTS_FILE}: {entry.strip()}")
        
        yield # The 'with' block in the main script runs here

    except Exception as e:
        console.log_error(f"An error occurred while managing hosts file: {e}")
    finally:
        # 3. Restore original content
        if original_content:
            hosts_path.write_text(original_content)
            console.log_info(f"Restored original {Config.HOSTS_FILE}.")


class ReconSuite:
    def __init__(self, target: str, options: argparse.Namespace):
        self.console = ConsoleManager()
        self.performance = PerformanceManager()
        self.target_ip = self._validate_and_resolve_target(target)
        self.hostname = options.hostname if options.hostname else f"{self.target_ip.replace('.', '-')}.ctf"
        
        self.quick_mode = options.quick
        self.output_dir = Path(options.output).resolve()
        self.scan_dir = self.output_dir / "scans"
        
        self.start_time = time.time()
        self.open_ports: List[Dict[str, Any]] = []
        self.web_urls: Set[str] = set()
        self.potential_vulns: Set[str] = set()
        
        # Configurações de performance baseadas no modo
        self._configure_performance()

    def _configure_performance(self):
        """Configura parâmetros de performance baseados no modo de execução."""
        if self.quick_mode:
            # Modo rápido: menos threads, timeouts menores
            Config.PERFORMANCE['max_workers'] = 2
            Config.PERFORMANCE['ffuf_threads'] = 20
            Config.PERFORMANCE['nmap_timing'] = 5  # Mais agressivo
            Config.TIMEOUTS['nmap_quick'] = 600  # Timeout menor
        else:
            # Modo normal: configurações padrão otimizadas
            Config.PERFORMANCE['max_workers'] = 4
            Config.PERFORMANCE['ffuf_threads'] = 40
            Config.PERFORMANCE['nmap_timing'] = 4

    def _validate_and_resolve_target(self, target: str) -> str:
        """Validates and resolves the target to an IP address."""
        try:
            # Simple check if it's an IP
            if all(0 <= int(octet) <= 255 for octet in target.split('.')) and len(target.split('.')) == 4:
                return target
            # If not, treat as hostname and resolve
            self.console.log_info(f"Resolving hostname: {target}...")
            result = subprocess.run(["getent", "hosts", target], capture_output=True, text=True, check=True)
            ip_address = result.stdout.strip().split()[0]
            self.console.log_success(f"Resolved {target} to {ip_address}")
            return ip_address
        except (ValueError, subprocess.CalledProcessError, IndexError):
            self.console.log_error(f"Invalid or unresolvable target: {target}")
            sys.exit(1)

    def _run_command(self, cmd: List[str], timeout: Optional[int] = None, use_cache: bool = True) -> subprocess.CompletedProcess:
        """Executes a command safely with optional caching."""
        # Gera hash do comando para cache
        cmd_hash = hash(tuple(cmd))
        
        # Verifica cache se habilitado
        if use_cache and Config.PERFORMANCE['enable_cache']:
            cached_result = self.performance.get_cached_result(str(cmd_hash))
            if cached_result:
                self.console.log_info(f"Using cached result for: {' '.join(cmd[:2])}...")
                # Reconstrói CompletedProcess do cache
                result = subprocess.CompletedProcess(
                    args=cmd,
                    returncode=cached_result['returncode'],
                    stdout=cached_result['stdout'],
                    stderr=cached_result['stderr']
                )
                return result
        
        try:
            # Executa comando com configurações otimizadas
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True,
                bufsize=8192  # Buffer maior para melhor performance
            )
            
            # Armazena no cache se habilitado
            if use_cache and Config.PERFORMANCE['enable_cache']:
                self.performance.set_cached_result(str(cmd_hash), {
                    'returncode': result.returncode,
                    'stdout': result.stdout,
                    'stderr': result.stderr
                })
            
            return result
            
        except FileNotFoundError:
            self.console.log_error(f"Command not found: {cmd[0]}. Please ensure it's installed and in your PATH.")
            raise
        except subprocess.TimeoutExpired:
            self.console.log_warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise
        except subprocess.CalledProcessError as e:
            self.console.log_error(f"Command failed: {' '.join(cmd)}")
            if e.stderr:
                self.console.log_error(f"Error details: {e.stderr.strip()}")
            raise
        except Exception as e:
            self.console.log_error(f"An unexpected error occurred: {e}")
            raise

    def _setup_environment(self):
        """Checks for required tools and creates output directories."""
        self.console.log_info("Setting up environment...", bold=True)
        # Check tools
        missing_tools = [tool for tool in Config.REQUIRED_TOOLS if not shutil.which(tool)]
        if missing_tools:
            self.console.log_error(f"Missing required tools: {', '.join(missing_tools)}. Please install them.")
            sys.exit(1)
        self.console.log_success("All required tools are present.")

        # Create directories
        for subdir in ["nmap", "ffuf", "whatweb", "exploits", "screenshots"]:
            (self.scan_dir / subdir).mkdir(parents=True, exist_ok=True)
        self.console.log_success(f"Output directory created at {self.output_dir}")

    def _scan_ports(self):
        """Performs optimized initial and detailed Nmap scans."""
        self.console.log_info(f"Starting optimized port scan on {self.target_ip}...", bold=True)
        
        # Configurações otimizadas baseadas no modo
        timing_template = f"-T{Config.PERFORMANCE['nmap_timing']}"
        nmap_base_cmd = ["nmap", timing_template, "--max-retries=2", self.target_ip]
        nmap_output_base = self.scan_dir / "nmap" / "scan_results"

        # Phase 1: Quick Scan for open ports (otimizado)
        with self.console.console.status("[bold yellow]Running optimized port scan...", spinner="dots"):
            if self.quick_mode:
                # Modo rápido: scan mais agressivo com menos portas
                scan_cmd = nmap_base_cmd + ["-F", "--open", "--max-retries=1", "--host-timeout=300s"]
            else:
                # Modo normal: scan completo otimizado
                scan_cmd = nmap_base_cmd + [
                    "-p-", 
                    f"--min-rate={1000 if not self.quick_mode else 2000}", 
                    "--open",
                    "--max-retries=2",
                    "--host-timeout=600s"
                ]
            
            try:
                result = self._run_command(scan_cmd, timeout=Config.TIMEOUTS['nmap_quick'])
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                self.console.log_error("Initial port scan failed. Aborting.")
                return

        ports_found = re.findall(r'(\d+)/tcp', result.stdout)
        if not ports_found:
            self.console.log_warning("No open TCP ports found.")
            return
        
        ports_str = ",".join(ports_found)
        self.console.log_success(f"Found {len(ports_found)} open ports: {ports_str}")
        
        # Phase 2: Detailed Scan on found ports (paralelo se múltiplas portas)
        self.console.log_info("Running detailed scan on discovered ports...", bold=True)
        
        if len(ports_found) > 10 and not self.quick_mode:
            # Para muitas portas, divide em grupos para paralelização
            self._parallel_detailed_scan(ports_found, nmap_output_base)
        else:
            # Scan normal para poucas portas
            detailed_cmd = [
                "nmap", "-sV", "-sC", "-p", ports_str, 
                "-oX", str(nmap_output_base) + ".xml",
                timing_template,
                self.target_ip
            ]
            
            with self.console.console.status("[bold yellow]Running detailed service scan...", spinner="dots"):
                try:
                    self._run_command(detailed_cmd, timeout=Config.TIMEOUTS['nmap_full'])
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    self.console.log_error("Detailed port scan failed. Continuing with partial data if available.")

        self._parse_nmap_xml(str(nmap_output_base) + ".xml")

    def _parallel_detailed_scan(self, ports_found: List[str], nmap_output_base: Path):
        """Executa scan detalhado em paralelo para muitas portas."""
        self.console.log_info(f"Running parallel detailed scan for {len(ports_found)} ports...")
        
        # Divide portas em grupos menores
        chunk_size = max(5, len(ports_found) // Config.PERFORMANCE['max_workers'])
        port_chunks = [ports_found[i:i + chunk_size] for i in range(0, len(ports_found), chunk_size)]
        
        timing_template = f"-T{Config.PERFORMANCE['nmap_timing']}"
        
        def scan_chunk(chunk_ports: List[str], chunk_id: int):
            """Executa scan em um chunk de portas."""
            ports_str = ",".join(chunk_ports)
            output_file = f"{nmap_output_base}_chunk_{chunk_id}.xml"
            
            cmd = [
                "nmap", "-sV", "-sC", "-p", ports_str,
                "-oX", output_file,
                timing_template,
                self.target_ip
            ]
            
            try:
                self._run_command(cmd, timeout=Config.TIMEOUTS['nmap_full'] // len(port_chunks))
                return output_file
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
                self.console.log_warning(f"Chunk {chunk_id} scan failed")
                return None
        
        # Executa scans em paralelo
        futures = []
        for i, chunk in enumerate(port_chunks):
            future = self.performance.executor.submit(scan_chunk, chunk, i)
            futures.append(future)
        
        # Coleta resultados
        successful_scans = []
        for future in as_completed(futures):
            result = future.result()
            if result:
                successful_scans.append(result)
        
        # Combina resultados XML se necessário
        if successful_scans:
            self._merge_nmap_xml_files(successful_scans, str(nmap_output_base) + ".xml")
            self.console.log_success(f"Completed parallel scan with {len(successful_scans)} successful chunks")

    def _merge_nmap_xml_files(self, xml_files: List[str], output_file: str):
        """Combina múltiplos arquivos XML do nmap em um único arquivo."""
        try:
            combined_root = ET.Element("nmaprun")
            combined_root.set("scanner", "nmap")
            combined_root.set("args", "combined scan")
            
            for xml_file in xml_files:
                if Path(xml_file).exists():
                    tree = ET.parse(xml_file)
                    root = tree.getroot()
                    
                    # Adiciona hosts encontrados
                    for host in root.findall("host"):
                        combined_root.append(host)
            
            # Salva arquivo combinado
            ET.ElementTree(combined_root).write(output_file, encoding="utf-8", xml_declaration=True)
            
        except Exception as e:
            self.console.log_warning(f"Failed to merge XML files: {e}")
            # Usa o primeiro arquivo como fallback
            if xml_files and Path(xml_files[0]).exists():
                shutil.copy2(xml_files[0], output_file)

    def _parse_nmap_xml(self, xml_file: str):
        """Parses Nmap XML output to extract port and service information."""
        if not Path(xml_file).exists():
            self.console.log_warning("Nmap XML output file not found. Skipping parsing.")
            return

        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for port_elem in root.findall(".//port"):
            state = port_elem.find("state").get("state")
            if state == "open":
                port_id = port_elem.get("portid")
                service_elem = port_elem.find("service")
                service = service_elem.get("name", "unknown")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                
                version_str = f"{product} {version}".strip()
                self.open_ports.append({
                    "port": port_id,
                    "service": service,
                    "version": version_str
                })
        
        if self.open_ports:
            table_rows = [[p['port'], p['service'], p['version']] for p in self.open_ports]
            self.console.print_table("Open Ports and Services", ["Port", "Service", "Version"], table_rows)
            self._identify_web_services()
        else:
            self.console.log_warning("Could not extract any open port details from Nmap scan.")

    def _identify_web_services(self):
        """Identifies web services based on common ports and service names."""
        web_indicators = ['http', 'www', 'ssl', 'https']
        for p in self.open_ports:
            if any(indicator in p['service'] for indicator in web_indicators) or int(p['port']) in [80, 443, 8000, 8080, 8443]:
                protocol = "https" if "ssl" in p['service'] or "https" in p['service'] or int(p['port']) in [443, 8443] else "http"
                self.web_urls.add(f"{protocol}://{self.target_ip}:{p['port']}")
                self.web_urls.add(f"{protocol}://{self.hostname}:{p['port']}")
        
        if self.web_urls:
            self.console.log_success(f"Identified {len(self.web_urls)} potential web URLs to investigate.")

    def _search_exploits(self):
        """Searches for exploits using searchsploit for discovered services."""
        if not self.open_ports:
            return
            
        self.console.log_info("Searching for exploits based on service versions...", bold=True)
        all_exploits = []
        
        with self.console.console.status("[bold yellow]Running searchsploit...", spinner="dots"):
            for service in self.open_ports:
                if service['version']:
                    query = f"{service['service']} {service['version']}"
                    try:
                        # Use -j for JSON output to make parsing reliable
                        result = self._run_command(["searchsploit", "-j", query.split()[0], query.split()[1] if len(query.split()) > 1 else ''])
                        exploits = json.loads(result.stdout).get("RESULTS_EXPLOIT", [])
                        if exploits:
                            self.console.log_success(f"Found {len(exploits)} potential exploits for {query}")
                            for exploit in exploits:
                                all_exploits.append([query, exploit.get('Title', 'N/A'), exploit.get('Path', 'N/A')])
                                self.potential_vulns.add(f"{query} - {exploit.get('Title', '')}")
                    except (subprocess.CalledProcessError, json.JSONDecodeError):
                        continue # Ignore if searchsploit finds nothing or fails for one service

        if all_exploits:
            self.console.print_table("Potential Exploits Found", ["Service", "Title", "Path"], all_exploits)

    def _scan_web(self):
        """Orchestrates scanning of discovered web services."""
        if not self.web_urls:
            self.console.log_warning("No web services to scan.")
            return

        self.console.log_info("Starting web reconnaissance...", bold=True)
        for url in self.web_urls:
            self.console.log_info(f"Scanning URL: {url}")
            self._run_whatweb(url)
            self._run_ffuf(url)
    
    def _run_whatweb(self, url: str):
        """Runs whatweb to identify web technologies."""
        self.console.log_info(f"Identifying technologies for {url} with WhatWeb...")
        safe_filename = url.replace('://', '_').replace(':', '_')
        output_file = self.scan_dir / "whatweb" / f"{safe_filename}.json"
        
        try:
            cmd = ["whatweb", "-a", "3", f"--log-json={output_file}", url]
            self._run_command(cmd, timeout=Config.TIMEOUTS['whatweb'])

            if output_file.exists() and output_file.stat().st_size > 0:
                with output_file.open('r') as f:
                    results = json.load(f)
                plugins = results[0].get('plugins', {})
                if plugins:
                    tech_list = []
                    for name, details in plugins.items():
                        version = " ".join(map(str, details.get("version", [])))
                        tech_list.append(f"{name} {version}".strip())
                    
                    self.console.log_success(f"Technologies found: [cyan]{', '.join(tech_list)}[/cyan]")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError, IndexError) as e:
            self.console.log_warning(f"WhatWeb scan failed for {url}: {e}")

    def _run_ffuf(self, url: str):
        """Runs optimized ffuf for content discovery."""
        self.console.log_info(f"Running optimized content discovery on {url} with ffuf...")
        safe_filename = url.replace('://', '_').replace(':', '_')
        output_file = self.scan_dir / "ffuf" / f"{safe_filename}.json"
        
        # Seleciona wordlist baseada no modo
        if self.quick_mode:
            wordlist = Config.WORDLISTS['common']
        else:
            wordlist = Config.WORDLISTS['dirs_medium']

        if not Path(wordlist).exists():
            self.console.log_warning(f"Wordlist not found at {wordlist}. Skipping ffuf scan for {url}.")
            return

        # Configurações otimizadas do ffuf
        threads = Config.PERFORMANCE['ffuf_threads']
        timeout = Config.TIMEOUTS['ffuf']
        
        cmd = [
            "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403", 
            "-t", str(threads),
            "-o", str(output_file), "-of", "json", 
            "-s",  # Silent mode
            "-e", "php,asp,aspx,jsp,html,htm,txt",  # Extensões comuns
            "-fs", "0",  # Filtrar tamanhos iguais a 0
            "-fw", "0",  # Filtrar palavras iguais a 0
            "-rate", "100" if self.quick_mode else "50"  # Rate limiting
        ]
        
        try:
            self._run_command(cmd, timeout=timeout)
            if output_file.exists() and output_file.stat().st_size > 0:
                with output_file.open('r') as f:
                    data = json.load(f)
                results = data.get('results', [])
                if results:
                    # Limita resultados exibidos para performance
                    display_results = results[:20] if len(results) > 20 else results
                    rows = [[str(r['status']), str(r['length']), r['url']] for r in display_results]
                    self.console.print_table(f"ffuf Results for {url} ({len(results)} total)", ["Status", "Size", "URL"], rows)
                    
                    if len(results) > 20:
                        self.console.log_info(f"... and {len(results) - 20} more results (see {output_file})")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError):
            self.console.log_warning(f"ffuf scan did not complete successfully for {url}.")
            
    def run(self):
        """Main execution flow of the reconnaissance suite with performance optimizations."""
        self.console.print_banner()
        self._setup_environment()
        
        hostnames_to_add = {self.hostname}
        
        with HostsManager(self.target_ip, hostnames_to_add):
            # Executa scan de portas primeiro (necessário para os outros)
            self._scan_ports()
            
            if self.open_ports:
                # Executa operações que podem ser paralelas após descobrir portas
                self._run_parallel_operations()
            else:
                self.console.log_warning("No open ports found. Skipping additional scans.")
        
        # Limpa recursos
        self.performance.shutdown()
        
        duration = time.time() - self.start_time
        self.console.log_success(f"Scan completed in {duration:.2f} seconds.")
        
        # Mostra estatísticas de performance
        self._show_performance_stats()

    def _run_parallel_operations(self):
        """Executa operações que podem rodar em paralelo."""
        self.console.log_info("Running parallel reconnaissance operations...", bold=True)
        
        # Prepara tarefas para execução paralela
        tasks = []
        
        # Busca de exploits (pode rodar independente)
        if not self.quick_mode:
            tasks.append(('exploits', self._search_exploits))
        
        # Scan web (pode rodar independente se há URLs web)
        if self.web_urls:
            tasks.append(('web_scan', self._scan_web))
        
        # Executa tarefas em paralelo se há múltiplas
        if len(tasks) > 1:
            futures = []
            for task_name, task_func in tasks:
                future = self.performance.executor.submit(task_func)
                futures.append((task_name, future))
            
            # Coleta resultados
            for task_name, future in futures:
                try:
                    future.result(timeout=Config.TIMEOUTS.get(f'{task_name}_timeout', 600))
                    self.console.log_success(f"Completed {task_name} scan")
                except Exception as e:
                    self.console.log_warning(f"{task_name} scan failed: {e}")
        else:
            # Executa sequencialmente se há apenas uma tarefa
            for task_name, task_func in tasks:
                try:
                    task_func()
                except Exception as e:
                    self.console.log_warning(f"{task_name} scan failed: {e}")

    def _show_performance_stats(self):
        """Mostra estatísticas de performance do scan."""
        if Config.PERFORMANCE['enable_cache']:
            cache_hits = len(self.performance.cache)
            if cache_hits > 0:
                self.console.log_info(f"Cache performance: {cache_hits} commands cached")
        
        ports_count = len(self.open_ports)
        urls_count = len(self.web_urls)
        vulns_count = len(self.potential_vulns)
        
        stats_table = [
            ["Open Ports", str(ports_count)],
            ["Web URLs", str(urls_count)],
            ["Potential Vulnerabilities", str(vulns_count)],
            ["Performance Mode", "Quick" if self.quick_mode else "Normal"]
        ]
        
        self.console.print_table("Scan Summary", ["Metric", "Value"], stats_table)

def main():
    parser = argparse.ArgumentParser(description="CTF Recon Suite - Automated Reconnaissance Tool")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-n", "--hostname", help="A custom primary hostname to use for the target (e.g., 'precious.htb')")
    parser.add_argument("-q", "--quick", action="store_true", help="Quick mode (less thorough but faster)")
    parser.add_argument("-o", "--output", default=Config.DEFAULT_OUTPUT_DIR, help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=Config.PERFORMANCE['max_workers'], 
                       help=f"Maximum parallel threads (default: {Config.PERFORMANCE['max_workers']})")
    parser.add_argument("--ffuf-threads", type=int, default=Config.PERFORMANCE['ffuf_threads'],
                       help=f"ffuf threads (default: {Config.PERFORMANCE['ffuf_threads']})")
    parser.add_argument("--nmap-timing", type=int, choices=range(6), default=Config.PERFORMANCE['nmap_timing'],
                       help=f"nmap timing template 0-5 (default: {Config.PERFORMANCE['nmap_timing']})")
    parser.add_argument("--no-cache", action="store_true", help="Disable command caching")
    parser.add_argument("--aggressive", action="store_true", help="Use aggressive scanning settings")
    args = parser.parse_args()

    # Aplica configurações de performance da linha de comando
    Config.PERFORMANCE['max_workers'] = args.threads
    Config.PERFORMANCE['ffuf_threads'] = args.ffuf_threads
    Config.PERFORMANCE['nmap_timing'] = args.nmap_timing
    Config.PERFORMANCE['enable_cache'] = not args.no_cache
    
    if args.aggressive:
        Config.PERFORMANCE['nmap_timing'] = 5
        Config.PERFORMANCE['ffuf_threads'] = min(100, args.ffuf_threads * 2)
        Config.TIMEOUTS['nmap_quick'] = 300  # Timeout mais agressivo

    def signal_handler(sig, frame):
        console = ConsoleManager()
        console.log_error("\nScan interrupted by user. Exiting gracefully.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        suite = ReconSuite(args.target, args)
        suite.run()
    except Exception as e:
        ConsoleManager().log_error(f"A critical error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
