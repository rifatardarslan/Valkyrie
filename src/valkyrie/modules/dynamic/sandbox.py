import os
import time
import tarfile
import tempfile
import threading
from typing import Dict, Any, Tuple
try:
    import docker
    from docker.errors import DockerException, APIError
except ImportError:
    docker = None
    DockerException = Exception
    APIError = Exception

class DockerSandbox:
    """Manages the lifecycle of an isolated Docker container for dynamic analysis."""
    
    def __init__(self, image_tag: str = "valkyrie-sandbox:latest", timeout_seconds: int = 15):
        if docker is None:
            self.client = None
            print("[-] Docker SDK not installed. Dynamic analysis will fail.")
        else:
            try:
                self.client = docker.from_env()
            except Exception as e:
                self.client = None
                print(f"[-] Docker daemon not running or accessible: {e}")
                
        self.image_tag = image_tag
        self.timeout = timeout_seconds
        self.container = None
        self.workspace_dir = "/sandbox"
        
    def _ensure_image_exists(self) -> bool:
        """Builds the sandbox image if it doesn't exist."""
        try:
            self.client.images.get(self.image_tag)
            return True
        except docker.errors.ImageNotFound:
            print("[*] Building sandbox image (this might take a minute)...")
            dockerfile_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "docker")
            try:
                self.client.images.build(path=dockerfile_path, dockerfile="ubuntu.Dockerfile", tag=self.image_tag)
                return True
            except Exception as e:
                print(f"[-] Failed to build image: {e}")
                return False

    def _copy_to_container(self, src: str, dst_dir: str):
        """Copies a file from host to container using tar streams."""
        # Create a temporary tar file
        fd, temp_tar_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)
        try:
            with tarfile.open(temp_tar_path, mode='w') as tar:
                tar.add(src, arcname=os.path.basename(src))
            
            with open(temp_tar_path, 'rb') as f:
                data = f.read()
                self.container.put_archive(dst_dir, data)
        finally:
            os.remove(temp_tar_path)

    def _copy_from_container(self, src_file: str, dest_dir: str) -> bool:
        """Extracts a file/folder from the container to the host."""
        try:
            strm, stat = self.container.get_archive(src_file)
            
            fd, temp_tar_path = tempfile.mkstemp(suffix=".tar")
            os.close(fd)
            try:
                with open(temp_tar_path, 'wb') as f:
                    for chunk in strm:
                        f.write(chunk)
                        
                with tarfile.open(temp_tar_path, mode='r') as tar:
                    tar.extractall(path=dest_dir)
                return True
            finally:
                os.remove(temp_tar_path)
        except docker.errors.NotFound:
            return False
        except Exception as e:
            print(f"[-] Error extracting from container: {e}")
            return False

    def execute(self, file_path: str) -> Dict[str, Any]:
        """Orchestrates the dynamic analysis."""
        result = {
            "success": False,
            "strace_log": None,
            "pcap_file": None,
            "error": None
        }
        
        try:
            if not self.client:
                result["error"] = "Docker SDK not installed or Docker daemon is unreachable."
                return result
                
            if not self._ensure_image_exists():
                result["error"] = "Failed to locate or build Docker image."
                return result

            # 1. Start Container
            # Use network_mode="none" for absolute isolation, but bridge allows PCAP capture easily. We'll use bridge.
            self.container = self.client.containers.run(
                self.image_tag,
                detach=True,
                tty=True,
                network_mode="bridge",
                cap_add=["SYS_PTRACE", "NET_ADMIN", "NET_RAW"], # Required for strace and tcpdump
                user="root" # Root to start tcpdump, then su to drop privileges
            )
            
            filename = os.path.basename(file_path)
            container_file_path = f"{self.workspace_dir}/{filename}"
            strace_out = f"{self.workspace_dir}/strace.log"
            pcap_out = f"{self.workspace_dir}/capture.pcap"
            
            # 2. Copy the sample
            self._copy_to_container(file_path, self.workspace_dir)
            self.container.exec_run(f"chmod +x {container_file_path}")
            self.container.exec_run(f"chown valkyrie:valkyrie {container_file_path}")
            
            # 3. Start PCAP capture (Background)
            tcpdump_cmd = f"tcpdump -i any -w {pcap_out} -U"
            self.container.exec_run(tcpdump_cmd, detach=True)
            time.sleep(1) # Let tcpdump initialize
            
            # 4. Execute Payload with Strace
            print(f"[*] Executing payload in sandbox for {self.timeout} seconds...")
            exec_cmd = f"su - valkyrie -c 'strace -f -s 1024 -o {strace_out} {container_file_path}'"
            
            # Run in a thread to enforce timeout
            exec_thread = threading.Thread(target=lambda: self.container.exec_run(exec_cmd))
            exec_thread.start()
            
            # Wait for process to establish, then capture memory before it exits
            # We'll sleep for half the timeout, grab the memories, then wait for finish.
            # In a real system, you'd hook the exit syscall, but this is a heuristic sandbox
            time.sleep(self.timeout // 2)
            
            # Find PID containing the payload executable name
            # strace runs it, so we need the pid of the child
            pid_search = self.container.exec_run(f"pgrep -f {filename}")
            pids = pid_search.output.decode('utf-8').strip().split('\n')
            
            maps_out = f"{self.workspace_dir}/maps.log"
            mem_out = f"{self.workspace_dir}/core.dmp"
            
            for pid in pids:
                if pid and pid.isdigit():
                    # Dump maps
                    self.container.exec_run(f"cp /proc/{pid}/maps {maps_out}")
                    # Dump core using gcore
                    self.container.exec_run(f"gcore -o {self.workspace_dir}/core {pid}")
                    # If multiple processes, just grab the first valid one or all, here we break after first successful map
                    if self.container.exec_run(f"ls {maps_out}").exit_code == 0:
                        break
                        
            exec_thread.join(timeout=(self.timeout // 2) + 2)
            
            # 5. Extract Artifacts
            # Create a tmp dir on host to hold outputs
            host_out_dir = tempfile.mkdtemp(prefix="valkyrie_dyn_")
            
            # Ensure pcap flushes by killing tcpdump
            self.container.exec_run("pkill tcpdump")
            time.sleep(1)
            
            if self._copy_from_container(strace_out, host_out_dir):
                result["strace_log"] = os.path.join(host_out_dir, "strace.log")
            
            if self._copy_from_container(pcap_out, host_out_dir):
                result["pcap_file"] = os.path.join(host_out_dir, "capture.pcap")
                
            if self._copy_from_container(maps_out, host_out_dir):
                result["maps_log"] = os.path.join(host_out_dir, "maps.log")
                
            # gcore outputs to core.<pid>
            core_files_cmd = self.container.exec_run(f"ls {self.workspace_dir}/core.*")
            if core_files_cmd.exit_code == 0:
                core_file_name = core_files_cmd.output.decode('utf-8').strip().split('\n')[0].split('/')[-1]
                if self._copy_from_container(f"{self.workspace_dir}/{core_file_name}", host_out_dir):
                    result["mem_dump"] = os.path.join(host_out_dir, core_file_name)
                
            result["success"] = True
            result["host_artifacts_dir"] = host_out_dir
            
        except DockerException as e:
            result["error"] = f"Docker error: {str(e)}"
        except Exception as e:
            result["error"] = str(e)
            
        finally:
            if self.container:
                # Force cleanup
                try:
                    self.container.kill()
                except APIError:
                    pass
                try:
                    self.container.remove(v=True, force=True)
                except APIError:
                    pass
                    
        return result
