#include "mainwindow.hh"

#include <QApplication>

int
main(int argc, char* argv[])
{
    QApplication a(argc, argv);
    MainWindow w;

    w.Init(argc, argv);

    w.show();

    int out = a.exec();
    w.updatePreferences();

    return out;
}
