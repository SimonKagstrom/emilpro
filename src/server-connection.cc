#include <server.hh>
#include <xmlfactory.hh>

#include <utils.hh>

using namespace emilpro;

void Server::registerListener(IListener &listener)
{
	unregisterListener(listener);
	m_listeners.push_back(&listener);
}

void Server::unregisterListener(IListener& listener)
{
	Server::Listeners_t::iterator found;

	for (Server::Listeners_t::iterator it = m_listeners.begin();
			it != m_listeners.end();
			++it) {
		if (*it == &listener)
			found = it;
	}

	if (found != m_listeners.end())
		m_listeners.erase(found);
}

void Server::setConnectionHandler(IConnectionHandler& handler)
{
	m_connectionHandler = &handler;
}

bool Server::connect()
{
	panic_if (!m_connectionHandler,
			"No connection handler");

	m_isConnected = m_connectionHandler->setup();

	return m_isConnected;
}

bool Server::sendXml(std::string& what)
{
	panic_if (!m_connectionHandler,
			"No connection handler");

	if (!m_isConnected)
		return false;

	// Send and receive XML
	std::string xml = m_connectionHandler->talk(what);

	// Handle the response
	return XmlFactory::instance().parse(xml, true);
}


static Server *g_server;

void Server::destroy()
{
	g_server = NULL;

	delete this;
}

Server& Server::instance()
{
	if (!g_server)
		g_server = new Server();

	return *g_server;
}

Server::Server() :
		m_connectionHandler(NULL),
		m_isConnected(false)
{
}

Server::~Server()
{
}
