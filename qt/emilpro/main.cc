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

    if (argc > 1)
    {
        if (auto err = w.LoadFile(argv[1]); err)
        {
            fmt::print("Error loading file: {}\n\n", err);
            Usage(argv[0]);
        }
    }

    w.show();

    auto out = QApplication::exec();
    w.UpdatePreferences();

    return out;
}
