#include <xmlfactory.hh>

#include <utils.hh>

using namespace emilpro;


XmlFactory::XmlFactory() :
		xmlpp::SaxParser(),
		m_validationRun(true),
		m_isRemote(false)
{
	set_substitute_entities(true);

	set_validate(true);
}


XmlFactory::~XmlFactory()
{
}

void XmlFactory::on_start_document()
{
}

void XmlFactory::on_end_document()
{
}

void XmlFactory::on_start_element(const Glib::ustring& name,
		const AttributeList& properties)
{
	if (m_validationRun)
		return;

	m_currentName = name;
	m_currentProperties = properties;

	XmlFactory::ElementToListenerMap_t::iterator it = m_elementListeners.find(m_currentName);

	if (it != m_elementListeners.end()) {
		XmlFactory::ListenerList_t *curLst = &it->second;

		m_listenerStack.push_back(curLst);
	}

	for (XmlFactory::ListenerStack_t::iterator itLst = m_listenerStack.begin();
			itLst != m_listenerStack.end();
			++itLst) {
		XmlFactory::ListenerList_t *curLst = *itLst;

		for (XmlFactory::ListenerList_t::iterator itListener = curLst->begin();
				itListener != curLst->end();
				++itListener) {
			XmlFactory::IXmlListener *cur = *itListener;

			cur->onStart(m_currentName, properties, "");
		}
	}

}

void XmlFactory::on_end_element(const Glib::ustring& name)
{
	if (m_validationRun)
		return;

	// For everything that currently listens
	for (XmlFactory::ListenerStack_t::iterator itLst = m_listenerStack.begin();
			itLst != m_listenerStack.end();
			++itLst) {
		XmlFactory::ListenerList_t *curLst = *itLst;

		for (XmlFactory::ListenerList_t::iterator itListener = curLst->begin();
				itListener != curLst->end();
				++itListener) {
			XmlFactory::IXmlListener *cur = *itListener;

			cur->onEnd(name);
		}
	}

	maybePopListener(name);

	m_currentName = "";
}

void XmlFactory::on_characters(const Glib::ustring& charactersIn)
{
	if (m_validationRun)
		return;

	if (m_currentName == "")
		return;

	std::string characters = unescape_string_from_xml(charactersIn);
	characters = trimString(characters);

	// For everything that currently listens
	for (XmlFactory::ListenerStack_t::iterator itLst = m_listenerStack.begin();
			itLst != m_listenerStack.end();
			++itLst) {
		XmlFactory::ListenerList_t *curLst = *itLst;

		for (XmlFactory::ListenerList_t::iterator itListener = curLst->begin();
				itListener != curLst->end();
				++itListener) {
			XmlFactory::IXmlListener *cur = *itListener;

			cur->onElement(m_currentName, m_currentProperties, characters);
		}
	}

	m_currentName = "";
	m_currentProperties.clear();
}

void XmlFactory::on_comment(const Glib::ustring& text)
{
}

void XmlFactory::on_warning(const Glib::ustring& text)
{
}

void XmlFactory::on_error(const Glib::ustring& text)
{
}

static XmlFactory *g_instance;
void XmlFactory::destroy()
{
	g_instance = NULL;

	delete this;
}

XmlFactory& XmlFactory::instance()
{
	if (!g_instance)
		g_instance = new XmlFactory();

	return *g_instance;
}

bool XmlFactory::parse(const std::string str, bool isRemote)
{
	bool out = true;

	m_mutex.lock();
	m_isRemote = isRemote;

	try {
		m_validationRun = true;
		parse_memory(str);
		m_validationRun = false;
		parse_memory(str);
	}
	catch(const xmlpp::exception& ex) {
		out = false;
	}
	m_mutex.unlock();

	return out;
}

void XmlFactory::registerListener(std::string elementName,
		IXmlListener* listener, bool prioritized)
{
	listener->setName(elementName);

	if (prioritized)
		m_elementListeners[elementName].push_front(listener);
	else
		m_elementListeners[elementName].push_back(listener);
}

void XmlFactory::unregisterListener(IXmlListener* listener)
{
	for (std::list<std::string>::iterator it = listener->m_names.begin();
			it != listener->m_names.end();
			++it)
		unregisterListenerName(listener, *it);
}

void XmlFactory::unregisterListenerName(IXmlListener *listener, const std::string &name)
{
	ListenerList_t &listeners = m_elementListeners[name];
	ListenerList_t::iterator found = listeners.end();

	for (ListenerList_t::iterator it = listeners.begin();
			it != listeners.end();
			++it) {
		if (*it == listener)
			found = it;
	}

	if (found != listeners.end())
		listeners.erase(found);

	if (listeners.size() == 0)
		m_elementListeners.erase(name);
}


void XmlFactory::on_fatal_error(const Glib::ustring& text)
{
}

bool XmlFactory::isParsingRemoteData()
{
	// Called with the lock held
	return m_isRemote;
}

void XmlFactory::maybePopListener(const Glib::ustring& name)
{
	if (m_listenerStack.empty())
		return;

	ListenerList_t *p = m_listenerStack.back();

	panic_if (p->empty(),
			"Listener stack list can't be empty");

	if (p->front()->hasName(name))
		m_listenerStack.pop_back();
}

