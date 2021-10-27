import sys  # sys нужен для передачи argv в QApplication
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog
from qtpy import QtGui
import design  # Это наш конвертированный файл дизайна
import parsers
import os


class ExampleApp(QtWidgets.QMainWindow, design.Ui_MainWindow):

    def __init__(self):
        # Это здесь нужно для доступа к переменным, методам
        # и т.д. в файле design.py
        super().__init__()
        self.setupUi(self)  # Это нужно для инициализации нашего дизайна
        self.radioButton.toggled.connect(self.radio1_clicked)
        self.radioButton_2.toggled.connect(self.radio2_clicked)
        self.pushButton_4.clicked.connect(self.selectFile_xml)
        self.pushButton_6.clicked.connect(self.generation_report)
        self.pushButton_5.clicked.connect(self.selectFile_csv)
        self.pushButton.clicked.connect(self.selectFile_xml_do)
        self.pushButton_2.clicked.connect(self.selectFile_xml_posle)

    def selectFile_xml(self):
        self.lineEdit.setText(QFileDialog.getOpenFileName(self, "Open File", "/", "XML Files (*.xml)")[0])

    def selectFile_xml_do(self):
        self.lineEdit_4.setText(QFileDialog.getOpenFileName(self, "Open File", "/", "XML Files (*.xml)")[0])

    def selectFile_xml_posle(self):
        self.lineEdit_5.setText(QFileDialog.getOpenFileName(self, "Open File", "/", "XML Files (*.xml)")[0])

    def selectFile_csv(self):
        self.lineEdit_2.setText(QFileDialog.getOpenFileName(self, "Open File", "/", "CSV Files (*.csv)")[0])

    def generation_report(self):
        if self.radioButton.isChecked():
            if self.lineEdit.text() != '':
                self.radioButton_2.setEnabled(False)
                file = self.lineEdit.text()
                file_soot = self.lineEdit_2.text()
                filename = 'report.csv'
                parsers.xml2csv(file, filename)
                parsers.modern(filename, file, file_soot)
                os.remove('report.csv')
                self.lineEdit_6.setText('Выполнено')
                self.radioButton_2.setEnabled(True)

        elif self.radioButton_2.isChecked():
            if (self.lineEdit_5.text() != '') and (self.lineEdit_4.text() != ''):
                self.radioButton.setEnabled(False)
                file_soot = self.lineEdit_2.text()
                file_do = self.lineEdit_4.text()
                file_posle = self.lineEdit_5.text()
                parsers.services(file_do, file_posle, file_soot)
                self.lineEdit_6.setText('Выполнено')
                self.radioButton.setEnabled(True)
                os.remove('rep_do.csv')
                os.remove('rep_posle.csv')

    def radio1_clicked(self, enabled):
        if enabled:
            self.lineEdit_6.setText('')
            self.pushButton_4.setEnabled(True)
            self.pushButton_5.setEnabled(True)
            self.pushButton.setEnabled(False)
            self.pushButton_2.setEnabled(False)
            self.pushButton_6.setEnabled(True)

    def radio2_clicked(self, enabled):
        if enabled:
            self.lineEdit_6.setText('')
            self.pushButton.setEnabled(True)
            self.pushButton_2.setEnabled(True)
            self.pushButton_4.setEnabled(False)
            self.pushButton_5.setEnabled(True)
            self.pushButton_6.setEnabled(True)


def main():
    app = QtWidgets.QApplication(sys.argv)  # Новый экземпляр QApplication
    window = ExampleApp()  # Создаём объект класса ExampleApp
    window.show()  # Показываем окно
    app.exec_()  # и запускаем приложение


if __name__ == '__main__':  # Если мы запускаем файл напрямую, а не импортируем
    main()  # то запускаем функцию main()
