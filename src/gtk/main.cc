#include <gtkmm.h>

#include <model.hh>

using namespace emilpro;

class EmilProGui
{
public:
	EmilProGui()
	{
	}

	void init(int argc, char **argv)
	{
		Glib::RefPtr<Gtk::Application> app = Gtk::Application::create(argc, argv, "org.gtkmm.example");

		Glib::RefPtr<Gtk::Builder> builder = Gtk::Builder::create_from_file("/home/ska/projects/emilpro/src/gtk/emilpro.glade");

		Gtk::Window * mainWindow = NULL;
		builder->get_widget("main window", mainWindow);

		app->run(*mainWindow);
	}

protected:
};

int main(int argc, char **argv)
{
	EmilProGui gui;

	gui.init(argc, argv);

	return 0;
}
