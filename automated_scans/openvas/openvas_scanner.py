from subprocess import call
import subprocess
from subprocess import call, check_output
import time
from time import sleep
from threading import Thread
import xml.etree.ElementTree as ET

class OpenvasScanner:

    def __init__(self):
        pass

    def run_openvas_scan(self, hosts, scan_id):
        # CREATE TARGET
        cmd_create_target = ['omp',
                             '--xml=<create_target><name>Targets</name><hosts>' + hosts + '</hosts><port_list>33d0cd82-57c6-11e1-8ed1-406186ea4fc5</port_list></create_target>',
                             '--username', 'admin', '--password', 'testingpassword', ]
        create_target_output = self.get_cmd_output_ascii(cmd_create_target)
        print('Creating Target')
        print(create_target_output)

        sleep(5)

        # GET TARGET
        cmd_get_targets = ["omp", "--get-targets", "--username", "admin", "--password", "testingpassword", ]
        cmd_get_targets_output = self.get_cmd_output_ascii(cmd_get_targets)
        target_id = cmd_get_targets_output.split(' ', 1)[0]
        print('Getting Target')
        print('Target Id:' + target_id)

        sleep(5)

        # CREATE TASK
        cmd_create_task = ['omp',
                           '--xml=<create_task><name>new_task</name><preferences><preference><scanner_name>source_iface</scanner_name><value>eth1</value></preference></preferences><config id="daba56c8-73ec-11df-a475-002264764cea"/><target id="' + target_id + '"/></create_task>',
                           '--username', 'admin', '--password', 'testingpassword', ]
        print('Creating Task')
        create_task_output = self.get_cmd_output_ascii(cmd_create_task)
        print(create_task_output)

        sleep(5)

        # GET TASK
        cmd_get_tasks = ["omp", "--get-tasks", "--username", "admin", "--password", "testingpassword", ]
        print('Getting Task')
        cmd_get_tasks_output = self.get_cmd_output_ascii(cmd_get_tasks)
        task_id = cmd_get_tasks_output.split(' ', 1)[0]
        print('Task Id:' + task_id)

        sleep(5)

        # START TASK
        cmd_start_task = ['omp', '--xml=<start_task task_id="' + task_id + '"/> ', '--username', 'admin', '--password',
                          'testingpassword', ]
        start_task_output = self.get_cmd_output_ascii(cmd_start_task)
        print('Starting Task: ' + start_task_output)

        while self.check_progress(task_id) != 'Done':
            sleep(5)

        # GET REPORTS
        cmd_get_reports = ['omp', '--xml=<get_reports /> ', '--username', 'admin', '--password',
                           'testingpassword', ]
        print('Getting Reports')
        cmd_get_reports_output = self.get_cmd_output_ascii(cmd_get_reports)
        report_id_key = 'report id='
        format_id_key = 'format_id'
        report_id = cmd_get_reports_output[
                    cmd_get_reports_output.index(report_id_key) + len(report_id_key) + 1:cmd_get_reports_output.index(
                        format_id_key) - 2]
        print('Report_id: ' + report_id)

        sleep(5)

        # GET REPORT
        print('Getting Report')
        cmd_get_report = ['omp', '--get-report', report_id, '--format', 'a994b278-1f62-11e1-96ac-406186ea4fc5',
                          '--username', 'admin', '--password', 'testingpassword', ]
        cmd_get_report_output = self.get_cmd_output_ascii(cmd_get_report)
        #print(cmd_get_report_output)

        sleep(5)

        #Store in file
        file_path = "/root/Desktop/FinalYearProjectRESTAPI/automated_scans/reports/"+str(scan_id)+".xml"
        file = open(file_path, "w")
        file.write(cmd_get_report_output)
        file.close()

        sleep(5)

        #DELETE TASK
        cmd_delete_task = ['omp', '--xml=<delete_task task_id="'+task_id+'"/> ', '--username', 'admin', '--password', 'testingpassword',]
        delete_task_output = self.get_cmd_output_ascii(cmd_delete_task)
        print('Deleting Task: ' + delete_task_output)

        sleep(5)

        #DELETE TARET
        cmd_delete_target = ['omp', '--xml=<delete_target target_id="'+target_id+'"/> ', '--username', 'admin', '--password', 'testingpassword',]
        delete_target_output = self.get_cmd_output_ascii(cmd_delete_target)
        print('Deleting Target: ' + delete_target_output)


        return file_path

    def check_progress(self, scan_id):
        print('Checking scan progress: ' + scan_id)
        params = ["omp", "--username", "admin", "--password", "testingpassword", "--get-tasks"]
        cmd = subprocess.Popen(params, stdout=subprocess.PIPE)
        cmd_out, cmd_err = cmd.communicate()
        my_output_list = cmd_out.decode("utf-8").split(" ")
        index = -1
        for word in my_output_list:
            index += 1
            if scan_id in word:
                scan_status = my_output_list[index + 2]
                print('Scan status: ' + scan_status)
                return scan_status

    def get_cmd_ouput(self, cmd):
        cmd = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        cmd_out, cmd_err = cmd.communicate()
        my_output_list = cmd_out.decode("utf-8").split(" ")
        return my_output_list

    def getXmlValue(self, root_element, attribute_to_find, data):
        root = data.getroot()
        for listing in root.findall(root_element):
            return listing.get(attribute_to_find)

    def call_system_command(self, cmd):
        print('Calling command: ' + str(cmd))
        return check_output(cmd)

    def get_cmd_output_ascii(self, cmd):
        cmd_output = self.call_system_command(cmd)
        return (cmd_output.decode('utf-8'))