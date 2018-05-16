import subprocess


class OpenvasScanner:

    def run_openvas_scan(self, hosts):
        scan_id = 'afbfd91c-37e2-4aca-bfd4-7ece0ef5365a'
        subprocess.call('omp --username admin --password testingpassword --start-task '+ scan_id, Shell=True)

    def check_progress(self, scan_id):
        print("Checking scan progress")
        finished = False
        output = subprocess.check_output('omp -u admin -w testingpassword --get-tasks', shell=True)
        my_output_list = output.decode("utf-8").split(" ")
        index = -1
        for word in my_output_list:
            index += 1
            if scan_id in word:
                scan_status = my_output_list[index + 2]
                return scan_status