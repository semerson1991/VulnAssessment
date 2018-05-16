from openvas_lib import report_parser


def getReport():
    print("Retrieving report")
    report = report_parser("/var/log/openvas/result.xml")
    return report