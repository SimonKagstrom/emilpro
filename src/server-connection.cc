#include <server.hh>
#include <xmlfactory.hh>

#include <utils.hh>

using namespace emilpro;

class ClientHandler : public XmlFactory::IXmlListener
{
public:
	ClientHandler() :
		m_instructionModelTimestamp(0)
	{
		XmlFactory::instance().registerListener("InstructionModel", this);
		XmlFactory::instance().registerListener("ServerTimestamps", this);
	}

	~ClientHandler()
	{
		XmlFactory::instance().unregisterListener(this);
	}

	bool sendTimestamps()
	{
		std::string xml = toXml();

		return Server::instance().sendXml(xml);
	}

private:
	std::string toXml()
	{
		return fmt(
				"  <ServerTimestamps>\n"
				"    <Timestamp>%llu</Timestamp>\n"
				"    <InstructionModelTimestamp>%llu</InstructionModelTimestamp>\n"
				"  </ServerTimestamps>\n",
				(unsigned long long)get_utc_timestamp(),
				(unsigned long long)m_instructionModelTimestamp);
	}


	// Derived
	bool onStart(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
	{
		if (name == "InstructionModel" && XmlFactory::instance().isParsingRemoteData()) {
			uint64_t timestamp = 0;

			for(xmlpp::SaxParser::AttributeList::const_iterator it = properties.begin();
					it != properties.end();
					++it) {
				if (it->name == "timestamp") {
					if (string_is_integer(it->value))
						timestamp = string_to_integer(it->value);
				}
			}

			maybeUpdateTimestamp(timestamp);
		}

		return true;
	}

	bool onElement(const Glib::ustring &name, const xmlpp::SaxParser::AttributeList &properties, std::string value)
	{
		if (name == "InstructionModelTimestamp") {
			uint64_t timestamp;

			if (string_is_integer(value))
				timestamp = string_to_integer(value);

			// Might have been updated by incoming data
			maybeUpdateTimestamp(timestamp);
		} else if (name == "ServerTimestampDiff") {

			// Difference between server timestmap and us
			if (string_is_integer(value))
				adjust_utc_timestamp(string_to_integer(value));
		}

		return true;
	}

	bool onEnd(const Glib::ustring &name)
	{
		return true;
	}

	void maybeUpdateTimestamp(uint64_t timestamp)
	{
		if (timestamp == 0)
			return;

		if (timestamp <= m_instructionModelTimestamp)
			return;

		m_instructionModelTimestamp = timestamp;
	}


	uint64_t m_instructionModelTimestamp;
};

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

	panic_if (m_isConnected,
			"Already connected");

	m_isConnected = m_connectionHandler->setup();

	if (m_isConnected)
		m_thread = new std::thread(&Server::threadMain, this);

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
		m_isConnected(false),
		m_timestampHolder(NULL),
		m_thread(NULL)
{
	m_timestampHolder = new ClientHandler();
}

Server::~Server()
{
	delete m_timestampHolder;

	if (m_thread)
		delete m_thread;
}

void Server::threadMain()
{
	/*
	 * We'll get the instruction models in the reply.
	 *
	 * For now, just exit the thread after this is done.
	 */
	m_timestampHolder->sendTimestamps();
}
