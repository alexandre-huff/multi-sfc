import psutil
import sys

if __name__ == '__main__':

    if len(sys.argv) != 2:
        print("Usage: python %s <PID>" % sys.argv[0])
        exit(1)

    PID = int(sys.argv[1])

    try:
        p = psutil.Process(PID)
    except:
        print("No process found with PID %s" % PID)
        exit(1)

    while True:
        cpu = p.cpu_percent(interval=1.0)
        ram = p.memory_percent()
        rss = p.memory_info()[0]
        # vms = p.memory_info()[1]

        for child in p.children(recursive=True):
            cpu += child.cpu_percent()
            ram += child.memory_percent()
            rss += p.memory_info()[0]

        with open('usage_data', 'a+') as f_usage:
            # f_usage.write(' '.join([str(cpu), str(ram)]) + '\n')
            f_usage.write(' '.join([str(cpu), str(ram), str(rss / float(2 ** 20))]) + '\n')
            # f_usage.write(' '.join([str(cpu), str(rss / float(2 ** 20)), str(vms / float(2 ** 20))]) + '\n')
