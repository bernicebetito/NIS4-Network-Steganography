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
            cpu = psutil.cpu_percent(interval)
            sheet1.write(row, 0, time)
            sheet1.write(row, 1, cpu)
            row += 1
            time += interval
            if row == 21:
                break
        wb.save("data.xls")
        print("Data collection stopped")
    
    except KeyboardInterrupt:
        input("Data collection stopped, press any key to continue...")
        wb.save("data.xls")

interval = 0.05
collect_data(float(interval))