import PySimpleGUI as psg

def main():
    layout = [
    [psg.Text('Threads to run: '), psg.Input()],
    [psg.Text('Address '), psg.Input()],
    [psg.Text('Email ID '), psg.Input()],
    [psg.OK(), psg.Exit()]
    ]
    window = psg.Window('Form', layout)
    while True:
        event, values = window.read()
        if event == psg.WIN_CLOSED or event == 'Exit':
            break
        print (event, values)
    window.close()

if __name__ == '__main__':
    main()
