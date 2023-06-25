import sys

EDF_data = {
    '1': {3: 25, 4: 29, 5: 34, 6: 31},
    '3': {3: 23, 4: 26, 5: -1, 6: 28, 7: -1},
    '4': {3: 25, 4: 28, 5: 28, 6: -1, 7: 52}
}

RM_data = {
    '2': ['4', '5', '3'],
    '5': ['3', '4', '5', '7'],
}

RMS_tid = ['2', '5']
EDF_tid = ['1', '3', '4']

test_id = sys.argv[1]

result = {
    'pid': [],
    'arrival_time': [],
    'absolute_deadline': []
}
if(test_id in RMS_tid):
    with open(f"res_assig2_{test_id}") as my_file:
        lines = my_file.readlines()
        for line in lines:
            result['pid'].append(line.split()[-1])

    if result['pid'] != RM_data[test_id]:
        print("FAIL")
        exit(1)

else:
    with open(f"res_assig2_{test_id}") as my_file:
        lines = my_file.readlines()
        for line in lines:
            result['pid'].append(line.split()[-1])
            result['arrival_time'].append(line.split()[-2])

            # The process should not have been scheduled.
            if(EDF_data[test_id][int(line.split()[-1])] == -1):
                print("FAIL")
                exit(1)

            result['absolute_deadline'].append(int(line.split()[-2]) + EDF_data[test_id][int(line.split()[-1])])

    prev_deadline = 0
    for deadline in result['absolute_deadline']:
        if(deadline < prev_deadline):
            print("FAIL")
            exit(1)

print("PASS")
