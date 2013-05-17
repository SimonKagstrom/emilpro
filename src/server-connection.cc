#include <server.hh>
#include <xmlfactory.hh>
#include <configuration.hh>
#include <utils.hh>

#include <curl/curl.h>
#include <string.h>

using namespace emilpro;

class CurlConnectionHandler : public Server::IConnectionHandler
{
public:
	CurlConnectionHandler()
	{
		curl_global_init(CURL_GLOBAL_ALL);

		m_curl = curl_easy_init();

		// Setup curl to read from memory
		curl_easy_setopt(m_curl, CURLOPT_URL, Configuration::instance().getServerUrl().c_str());
		curl_easy_setopt(m_curl, CURLOPT_READFUNCTION, curlReadFuncStatic);
		curl_easy_setopt(m_curl, CURLOPT_READDATA, (void *)this);
		curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, curlWriteFuncStatic);
		curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, (void *)this);
		curl_easy_setopt(m_curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	}

	~CurlConnectionHandler()
	{
		curl_easy_cleanup(m_curl);
		curl_global_cleanup();
	}


	bool setup(void)
	{
		return true;
	}

	std::string talk(const std::string &xml)
	{
		m_bodyPos = 0;
		m_bodySize = xml.size();
		m_data = (void *)xml.c_str();

		struct curl_httppost *formpost = NULL;
		struct curl_httppost *lastptr = NULL;
		CURLcode res;

		curl_formadd(&formpost,
				&lastptr,
				CURLFORM_COPYNAME, "sendfile",
				CURLFORM_FILE, "postit2.c",
				CURLFORM_END);

		curl_formadd(&formpost,
				&lastptr,
				CURLFORM_COPYNAME, "submit",
				CURLFORM_COPYCONTENTS, "send",
				CURLFORM_END);

		curl_easy_setopt(m_curl, CURLOPT_HTTPPOST, formpost);

		res = curl_easy_perform(m_curl);

		curl_formfree(formpost);

		if (res != CURLE_OK)
			return "";

		return ""; // FIXME!
	}

private:
	size_t curlReadfunc(void *ptr, size_t size, size_t nmemb)
	{
		int available = (m_bodySize - m_bodyPos);

		if (available <= 0)
			return 0;

		int written = size * nmemb;

		if (written > available)
			written = available;

		memcpy(ptr, ((char*)(m_data)) + m_bodyPos, written);
		m_bodyPos += written;

		return written;
	}

	size_t curlWritefunc(void *ptr, size_t size, size_t nmemb)
	{
		return 0;
	}

	static size_t curlReadFuncStatic(void *ptr, size_t size, size_t nmemb, void *priv)
	{
		if (!priv)
			return 0;

		return ((CurlConnectionHandler *)priv)->curlReadfunc(ptr, size, nmemb);
	}

	static size_t curlWriteFuncStatic(void *ptr, size_t size, size_t nmemb, void *priv)
	{
		if (!priv)
			return 0;

		return ((CurlConnectionHandler *)priv)->curlWritefunc(ptr, size, nmemb);
	}

	CURL *m_curl;

	int m_bodySize;
	int m_bodyPos;
	void *m_data;
};


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
	if (m_connectionHandler)
		delete m_connectionHandler;

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

	CurlConnectionHandler *ch = new CurlConnectionHandler();

	setConnectionHandler(*ch);
}

Server::~Server()
{
	delete m_timestampHolder;

	if (m_connectionHandler)
		delete m_connectionHandler;

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
