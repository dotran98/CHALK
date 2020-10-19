import base64
from io import BytesIO
from PyQt5 import QtCore, QtGui, QtWidgets
import sys
from Label import Label
from Graph import Graph
import CHALK_dataAnalysis as da
from PDF import PDF
from CHALKscan import Scan

class Ui_MainWindow(QtWidgets.QMainWindow):
    resized = QtCore.pyqtSignal()
    data_hub = da.Data_Analysis()
    bio = BytesIO()
    scan = Scan()

    def __init__(self, parent=None):
        # Main Window
        super(Ui_MainWindow, self).__init__(parent=parent)
        self.setObjectName("MainWindow")
        self.resize(1233, 883)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        self.setFont(font)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icon\logo.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.setWindowIcon(icon)
        self.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.setWindowTitle("CHALK")

        # Tool bar
        tool_bar = QtWidgets.QToolBar('Toolbar', self)
        tool_bar.setObjectName("ToolBar")
        scanning = QtWidgets.QAction(QtGui.QIcon('icon\play.png'), 'Scan', self)
        scanning.setShortcut('Space')
        scanning.triggered.connect(self.__scan)
        scanning.setObjectName("Scanning")
        tool_bar.addAction(scanning)
        importing = QtWidgets.QAction(QtGui.QIcon('icon\import.png'), 'Import', self)
        importing.triggered.connect(self.__import)
        importing.setShortcut('Ctrl+O')
        importing.setObjectName("Importing")
        tool_bar.addAction(importing)
        exporting = QtWidgets.QAction(QtGui.QIcon('icon\export.png'), 'Export', self)
        exporting.triggered.connect(self.__export)
        exporting.setShortcut('Ctrl+S')
        exporting.setObjectName("Exporting")
        tool_bar.addAction(exporting)
        self.addToolBar(tool_bar)

        # Central Widget
        self.centralwidget = QtWidgets.QStackedWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.setCentralWidget(self.centralwidget)

        # Welcome Widget
        self.welcomewidget = QtWidgets.QWidget()
        horizontallayout = QtWidgets.QHBoxLayout(self.welcomewidget)
        label = Label(self.welcomewidget)
        piximap = QtGui.QPixmap('icon\welcome.png')
        label.setPixmap(piximap)
        horizontallayout.addWidget(label)
        self.centralwidget.addWidget(self.welcomewidget)

        # Result widget
        self.result_widget = QtWidgets.QWidget()
        horizontalLayout = QtWidgets.QHBoxLayout(self.result_widget)
        horizontalLayout.setContentsMargins(0, 0, 0, 0)

        self.tabWidget = QtWidgets.QTabWidget(self.result_widget)
        horizontalLayout.addWidget(self.tabWidget)

        line = QtWidgets.QFrame(self.result_widget)
        line.setFrameShape(QtWidgets.QFrame.VLine)
        line.setFrameShadow(QtWidgets.QFrame.Sunken)
        horizontalLayout.addWidget(line)

        listView = QtWidgets.QListView(self.result_widget)
        horizontalLayout.addWidget(listView, 0, QtCore.Qt.AlignRight)
        self.centralwidget.addWidget(self.result_widget)

        # Waiting widget
        self.waiting_widget = QtWidgets.QLabel()
        self.centralwidget.addWidget(self.waiting_widget)
        self.centralwidget.setCurrentIndex(0)


    # Whenever resize occur, it emits signal to resize gif
    def resizeEvent(self, event):
        self.resized.emit()
        return super(Ui_MainWindow, self).resizeEvent(event)

    def _resizeGif(self):
        rect = self.centralwidget.geometry()
        size = QtCore.QSize(rect.width(), rect.height())
        self.gif.setScaledSize(size)
        self.waiting_widget.setMovie(self.gif)
        self.gif.start()

    # Scanning function toolbar
    def __scan(self):
        try:
            self.gif = QtGui.QMovie('icon\waiting.gif')
            rect = self.centralwidget.geometry()
            size = QtCore.QSize(rect.width(), rect.height())
            self.gif.setScaledSize(size)
            self.waiting_widget.setMovie(self.gif)
            self.gif.start()
            self.resized.connect(self._resizeGif)
            self.centralwidget.setCurrentIndex(2)
        except Exception as e:
            print(e)
        """self.scan.run() # run the scan
        self.data_hub.analyseData('finalresult.csv') # process the csv file
        self.display_result() # display network visualization"""

    def display_result(self):
        try:
            tab = Graph(self.data_hub.systemList)
            tab.draw_idle()
            tab.figure.savefig(self.bio, format="png")
            self.tabWidget.addTab(tab, "Network")
        except Exception as e:
            print(e)

        self.centralwidget.setCurrentIndex(1)

    # Import function toolbar
    def __import(self):
        filename_path, ok = QtWidgets.QFileDialog.getOpenFileName(self,
                                                                  "Open File",
                                                                  "",
                                                                  "All Files (*);;Text Files (*.txt)")
        if ok:
            self.data_hub.analyseData(filename_path)
            self.display_result()

    # Export function toolbar
    def __export(self):
        try:
            result = QtWidgets.QFileDialog.getSaveFileName(self,
                                                           'Save File', '',
                                                           "PDF (*.pdf)")
            file_path = result[0]
            # Create PDF
            pdf = PDF(orientation='P', unit='mm', format='A4')
            pdf.set_top_margin(20.0)
            pdf.add_page()
            # Name of the report
            page_width = pdf.w - 2 * pdf.l_margin
            pdf.set_font('Times', 'B', 20.0)
            pdf.cell(page_width, 0.0, 'Network Report', align='C')
            pdf.ln(10)
            # List of system details
            pdf.set_font('Times', 'B', 16.0)
            pdf.cell(page_width, 0.0, '1. System List:')
            pdf.ln(8)
            pdf.set_font('Times', '', 14)
            for system in self.data_hub.systemList:
                pdf.cell(10, 0.0)
                pdf.multi_cell(page_width-20, 5.0, "System ID: " + str(system.SystemID))
                pdf.ln(5)
                pdf.cell(20, 0.0)
                pdf.multi_cell(page_width-30, 5.0, "IP: " + str(system.ipAddress))
                pdf.ln(5)
                pdf.cell(20, 0.0)
                pdf.multi_cell(page_width-30, 5.0, "Operating System:" + str(system.operatingSystem))
                pdf.ln(5)
                pdf.cell(20, 0.0)
                pdf.multi_cell(page_width-30, 5.0, "Open Ports and Services: {}".format(system.numOpenPorts))
                pdf.ln(5)
                for port in system.openPorts[0]:
                    pdf.cell(30, 0.0)
                    portNumber = "{}: ".format(port[0]) + port[1].split(' ')[1]
                    pdf.cell(page_width, 0.0, portNumber)
                    pdf.ln(5)
                    temp = port[2].split('{')
                    for details in temp:
                        if len(details) > 20:
                            details = details.split(',')
                            pdf.cell(40, 0.0)
                            pdf.multi_cell(page_width-50, 5.0, "State: "+details[0].split(':')[1].replace("'", ''))
                            pdf.ln(5)
                            pdf.cell(40, 0.0)
                            pdf.multi_cell(page_width-50, 5.0, "Product: " + details[3].split(':')[1].replace("'", ''))
                            pdf.ln(5)
                            pdf.cell(40, 0.0)
                            pdf.multi_cell(page_width-50, 5.0, "Version: " + details[4].split(':')[1].replace("'", ''))
                            pdf.ln(5)
                            pdf.cell(40, 0.0)
                            pdf.multi_cell(page_width-50, 5.0, "Extra Information: " + details[5].split(':')[1].replace("'", ''))
                            pdf.ln(5)
                            pdf.cell(40, 0.0)
                            pdf.multi_cell(page_width-50, 5.0, "Configuration: " + details[6].split(':')[1].replace("'", ''))
                            pdf.ln(5)
                            pdf.cell(40, 0.0)
                            pdf.multi_cell(page_width-50, 5.0, "CPE: " + details[7].split(':')[1].replace("'", ''))
                            pdf.ln(5)
                pdf.cell(20, 0.0)
                pdf.cell(page_width-30, 5.0, "Vulnerabilities: " + str(system.numberVulnerabilities))
                pdf.ln(5)
                for vul in system.vulnerabilities:
                    pdf.cell(30, 0.0)
                    pdf.multi_cell(page_width-50, 5.0, str(vul))
                    pdf.ln(5)
                pdf.cell(20, 0.0)
                pdf.cell(page_width, 0.0, "System Ranking:" + str(system.systemRanking))
                pdf.ln(10)
            pdf.set_top_margin(10.0)
            pdf.add_page(orientation='L')  # This page is for network visualization
            pdf.set_font('Times', 'B', 16.0)
            pdf.cell(page_width, 0.0, '2. Network Visualization:')
            pdf.ln(5)
            graph_path = 'data:image/png;base64,{}'.format(base64.b64encode(self.bio.getvalue()).decode())
            pdf.image(name=graph_path, type='png')
            pdf.output(file_path)
        except Exception as e:
            print(e)
        finally:
            print('Done')


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    ui = Ui_MainWindow()
    ui.show()
    sys.exit(app.exec_())
