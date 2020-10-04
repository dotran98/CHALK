import base64
from io import BytesIO

from PyQt5 import QtCore, QtGui, QtWidgets
import sys
from Label import Label
from Graph import Graph
import CHALK_dataAnalysis as da
from PDF import PDF


class Ui_MainWindow(object):
    def __init__(self):
        self.data_hub = da.Data_Analysis()
        self.bio = BytesIO()

    def setupUi(self, MainWindow):
        # Main Window
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1233, 883)
        font = QtGui.QFont()
        font.setBold(False)
        font.setWeight(50)
        MainWindow.setFont(font)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("icon\logo.jpg"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setLayoutDirection(QtCore.Qt.LeftToRight)

        # Tool bar
        tool_bar = QtWidgets.QToolBar('Toolbar', MainWindow)
        tool_bar.setObjectName("ToolBar")
        scanning = QtWidgets.QAction(QtGui.QIcon('icon\play.png'), 'Scan', MainWindow)
        scanning.setShortcut('Space')
        scanning.triggered.connect(self.__scan)
        scanning.setObjectName("Scanning")
        tool_bar.addAction(scanning)
        importing = QtWidgets.QAction(QtGui.QIcon('icon\import.png'), 'Import', MainWindow)
        importing.triggered.connect(self.__import)
        importing.setShortcut('Ctrl+O')
        importing.setObjectName("Importing")
        tool_bar.addAction(importing)
        exporting = QtWidgets.QAction(QtGui.QIcon('icon\export.png'), 'Export', MainWindow)
        exporting.triggered.connect(self.__export)
        exporting.setShortcut('Ctrl+S')
        exporting.setObjectName("Exporting")
        tool_bar.addAction(exporting)
        MainWindow.addToolBar(tool_bar)

        # Central Widget
        self.centralwidget = QtWidgets.QStackedWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        MainWindow.setCentralWidget(self.centralwidget)

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

        self.retranslateUi(MainWindow)
        self.centralwidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "CHALK"))

    # Scanning function toolbar
    def __scan(self):
        self.centralwidget.setCurrentIndex(0)

    def display_result(self):
        try:
            tab = Graph(self.data_hub.system_list)
            tab.draw_idle()
            tab.figure.savefig(self.bio, format="png")
            self.tabWidget.addTab(tab, "Network")
        except Exception as e:
            print(e)

        self.centralwidget.setCurrentIndex(1)

    # Import function toolbar
    def __import(self):
        filename_path, ok = QtWidgets.QFileDialog.getOpenFileName(MainWindow,
                                                                  "Open File",
                                                                  "",
                                                                  "All Files (*);;Text Files (*.txt)")
        if ok:
            self.data_hub.offline_analyse_data(filename_path)
            self.display_result()

    # Export function toolbar
    def __export(self):
        try:
            result = QtWidgets.QFileDialog.getSaveFileName(MainWindow,
                                                           'Save File', '',
                                                           "PDF (*.pdf)")
            file_path = result[0]
            # Create PDF
            pdf = PDF(orientation='P', unit='mm', format='A4')
            pdf.add_page()
            # Name of the report
            page_width = pdf.w - 2 * pdf.l_margin
            pdf.set_font('Times', 'B', 20.0)
            pdf.cell(page_width, 0.0, 'Network Report', align='C')
            pdf.ln(10)
            # List of system details
            pdf.set_font('Times', 'B', 16.0)
            pdf.cell(page_width, 0.0, '1. System List:')
            pdf.ln(10)
            pdf.set_font('Times', '', 14)
            for system in self.data_hub.system_list:
                pdf.cell(10, 0.0)
                pdf.cell(page_width, 0.0, "System ID: " + str(system.SystemID))
                pdf.ln(10)
                pdf.cell(20, 0.0)
                pdf.cell(page_width, 0.0, "IP: " + str(system.ip_address))
                pdf.ln(10)
                pdf.cell(20, 0.0)
                pdf.cell(page_width, 0.0, "Operating System:" + str(system.operatingSystem))
                pdf.ln(10)
                pdf.cell(20, 0.0)
                pdf.cell(page_width, 0.0, "Ports and Services: {}".format(system.numOpenPorts))
                pdf.ln(10)
                for port in system.openPorts:
                    pdf.cell(30, 0.0)
                    pdf.cell(page_width, 0.0, port[0])
                    pdf.ln(10)
                pdf.cell(20, 0.0)
                pdf.cell(page_width, 0.0, "Vulnerabilities: " + str(system.numberVulnerabilities))
                pdf.ln(10)
                for vul in system.vulnerabilities:
                    pdf.cell(30, 0.0)
                    pdf.cell(page_width, 0.0, str(vul))
                    pdf.ln(10)

            pdf.add_page(orientation='L')  # This page is for network visualization
            pdf.set_font('Times', 'B', 16.0)
            pdf.cell(page_width, 0.0, '2. Network Visualization:')
            pdf.ln(5)
            graph_path = 'data:image/png;base64,{}'.format(base64.b64encode(self.bio.getvalue()).decode())
            print(graph_path)
            pdf.image(name=graph_path, type='png')
            pdf.output(file_path)
        except Exception as e:
            print(e)
        finally:
            print('Done')


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
