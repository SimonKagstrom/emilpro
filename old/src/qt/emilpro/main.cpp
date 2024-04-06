#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;

    w.init(argc, argv);

    w.show();
    
    int out = a.exec();
    w.updatePreferences();

    return out;
}
