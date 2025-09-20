import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import argparse

# Import the ReconSuite class
from ctf_hero2 import ReconSuite, ConsoleManager, Config

@pytest.fixture
def temp_output_dir():
    """Cria um diretório temporário para saídas de teste."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir

@pytest.fixture
def mock_args():
    """Cria argumentos mock para ReconSuite."""
    args = argparse.Namespace()
    args.hostname = None
    args.quick = False
    args.output = "test_output"
    return args

@pytest.fixture
def recon_suite(mock_args):
    """Cria uma instância ReconSuite com configuração de teste."""
    return ReconSuite("127.0.0.1", mock_args)

def test_recon_suite_init(recon_suite):
    """Testa a inicialização do ReconSuite."""
    assert recon_suite.target_ip == "127.0.0.1"
    assert recon_suite.hostname == "127-0-0-1.ctf"
    assert recon_suite.quick_mode is False
    assert isinstance(recon_suite.open_ports, list)
    assert isinstance(recon_suite.web_urls, set)
    assert isinstance(recon_suite.potential_vulns, set)

def test_validate_and_resolve_target():
    """Testa a validação e resolução de alvos."""
    args = argparse.Namespace()
    args.hostname = None
    args.quick = False
    args.output = "test_output"
    
    # Teste com IP válido
    suite = ReconSuite("192.168.1.1", args)
    assert suite.target_ip == "192.168.1.1"
    
    # Teste com IP inválido
    with pytest.raises(SystemExit):
        ReconSuite("999.999.999.999", args)

def test_setup_environment(recon_suite):
    """Testa a configuração do ambiente."""
    with patch('shutil.which') as mock_which:
        mock_which.return_value = True  # Simula que todas as ferramentas estão disponíveis
        
        with patch('pathlib.Path.mkdir') as mock_mkdir:
            recon_suite._setup_environment()
            # Verifica se os diretórios foram criados
            assert mock_mkdir.called

def test_identify_web_services(recon_suite):
    """Testa a identificação de serviços web."""
    # Adiciona algumas portas mock
    recon_suite.open_ports = [
        {"port": "80", "service": "http", "version": "Apache 2.4"},
        {"port": "443", "service": "https", "version": "nginx 1.18"},
        {"port": "22", "service": "ssh", "version": "OpenSSH 8.2"}
    ]
    
    recon_suite._identify_web_services()
    
    # Verifica se URLs web foram identificadas
    assert len(recon_suite.web_urls) > 0
    assert any("http://127.0.0.1:80" in url for url in recon_suite.web_urls)
    assert any("https://127.0.0.1:443" in url for url in recon_suite.web_urls)

def test_console_manager():
    """Testa o ConsoleManager."""
    console = ConsoleManager()
    assert console.console is not None
    
    # Testa os métodos de log (não devem levantar exceções)
    console.log_info("Test info")
    console.log_success("Test success")
    console.log_warning("Test warning")
    console.log_error("Test error")

def test_config():
    """Testa a classe Config."""
    assert Config.HOSTS_FILE == "/etc/hosts"
    assert Config.DEFAULT_OUTPUT_DIR == "output"
    assert "nmap" in Config.REQUIRED_TOOLS
    assert "ffuf" in Config.REQUIRED_TOOLS
    assert "whatweb" in Config.REQUIRED_TOOLS
    assert isinstance(Config.TIMEOUTS, dict)
    assert "nmap_quick" in Config.TIMEOUTS

def test_run_command(recon_suite):
    """Testa a execução segura de comandos."""
    with patch('subprocess.run') as mock_run:
        mock_run.return_value.stdout = "test output"
        mock_run.return_value.returncode = 0
        
        result = recon_suite._run_command(["echo", "test"])
        assert result.stdout == "test output"
        
        # Teste de timeout
        mock_run.side_effect = TimeoutError()
        with pytest.raises(TimeoutError):
            recon_suite._run_command(["sleep", "10"], timeout=1)

def test_hosts_manager():
    """Testa o HostsManager context manager."""
    from ctf_hero2 import HostsManager
    
    with patch('os.geteuid', return_value=0):  # Simula root
        with patch('pathlib.Path.exists', return_value=True):
            with patch('pathlib.Path.read_text', return_value="original content"):
                with patch('pathlib.Path.open', mock_open()):
                    with patch('pathlib.Path.write_text') as mock_write:
                        with HostsManager("192.168.1.1", {"test.htb"}):
                            pass
                        # Verifica se o arquivo foi restaurado
                        mock_write.assert_called_with("original content") 