#include "mainwindow.hh"

#include <QApplication>
#include <QFile>
#include <fmt/format.h>
#include <stdlib.h>

namespace
{

void
Usage(auto app_name)
{
    fmt::print("Usage: {} [filename]\n", app_name);
    exit(1);
}

} // namespace

int
main(int argc, char* argv[])
{
    QApplication a(argc, argv);

    if (argc > 1 && !QFile(argv[1]).exists())
    {
        fmt::print("File {} not found\n\n", argv[1]);
        Usage(argv[0]);
    }

    MainWindow w;
    w.Init(argc, argv);

    w.show();

    int out = a.exec();
    w.UpdatePreferences();

    return out;
}
