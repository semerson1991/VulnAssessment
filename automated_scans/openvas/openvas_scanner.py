from subprocess import call
import subprocess

class OpenvasScanner:

    def __init__(self):
        pass

    def run_openvas_scan(self, hosts):
        scan_id = 'afbfd91c-37e2-4aca-bfd4-7ece0ef5365a' #NEED TO CALL openvas-start To start the service!
        cmd = ["omp", "--username", "admin", "--password", "testingpassword", "--start-task", scan_id ]
        call(cmd)

    def check_progress(self, scan_id):
        print("Checking scan progress")
        params = ["omp", "--username", "admin", "--password", "testingpassword", "--get-tasks"]
        cmd = subprocess.Popen(params, stdout=subprocess.PIPE)
        cmd_out, cmd_err = cmd.communicate()
        my_output_list = cmd_out.decode("utf-8").split(" ")
        index = -1
        for word in my_output_list:
            index += 1
            if scan_id in word:
                scan_status = my_output_list[index + 2]
                #return scan_status
                return 'Done'