from PyQt5 import QtCore, QtGui, QtWidgets
import sys
from Label import Label
from Graph import Graph
import CHALK_dataAnalysis as da


class Ui_MainWindow(object):
    def __init__(self):
        self.data_hub = da.Data_Analysis()

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
        scanning.triggered.connect(self.__scan)
        scanning.setObjectName("Scanning")
        tool_bar.addAction(scanning)
        importing = QtWidgets.QAction(QtGui.QIcon('icon\import.png'), 'Import', MainWindow)
        importing.triggered.connect(self.__import)
        importing.setObjectName("Importing")
        tool_bar.addAction(importing)
        exporting = QtWidgets.QAction(QtGui.QIcon('icon\export.png'), 'Export', MainWindow)
        exporting.triggered.connect(self.__export)
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
        tab = Graph(self.data_hub.system_list)
        tab.draw_idle()
        self.tabWidget.addTab(tab, "Network")

        self.centralwidget.setCurrentIndex(1)

    # Import function toolbar
    def __import(self):
        filename_path, ok = QtWidgets.QFileDialog.getOpenFileName(MainWindow,
                                                                  "Open File",
                                                                  "C:/",
                                                                  "All Files (*);;Text Files (*.txt)")
        if ok:
            self.data_hub.offline_analyse_data(filename_path)
            self.display_result()

    # Export function toolbar
    def __export(self):
        print('Exporting')


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
