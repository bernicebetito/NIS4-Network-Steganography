import psutil
import xlwt
from xlwt import Workbook

def collect_data(interval):
    wb = Workbook()
    sheet1 = wb.add_sheet('CPU USAGE')
    row = 1
    time = 0
    sheet1.write(0, 0, "Seconds")
    sheet1.write(0, 1, "CPU Usage")
    print("Data collection started")
    try:
        while True:
            sheet1.write(row, 0, time)
            sheet1.write(row, 1, psutil.cpu_percent(interval))
            row += 1
            time += interval
            if row == 10:
                break
        wb.save("data.xls")
    
    except KeyboardInterrupt:
        input("Data collection stopped, press any key to continue...")
        wb.save("data.xls")

interval = input("Select interval in seconds for collecting CPU usage: ")
collect_data(float(interval))