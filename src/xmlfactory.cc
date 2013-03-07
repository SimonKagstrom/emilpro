#include <xmlfactory.hh>

#include <utils.hh>

using namespace emilpro;


XmlFactory::XmlFactory() :
		xmlpp::SaxParser(),
		m_validationRun(true)
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
}

void XmlFactory::on_characters(const Glib::ustring& characters)
{
	if (m_validationRun)
		return;

	if (m_currentName == "")
		return;

	XmlFactory::ElementToListenerMap_t::iterator it = m_elementListeners.find(m_currentName);

	if (it != m_elementListeners.end()) {
		XmlFactory::ListenerList_t *curLst = &it->second;

		m_listenerStack.push_back(curLst);
	}

	// For everything that currently listens
	for (XmlFactory::ListenerStack_t::iterator itLst = m_listenerStack.begin();
			itLst != m_listenerStack.end();
			++itLst) {
		XmlFactory::ListenerList_t *curLst = *itLst;

		for (XmlFactory::ListenerList_t::iterator itListener = curLst->begin();
				itListener != curLst->end();
				++itListener) {
			XmlFactory::IXmlListener *cur = *itListener;

			if (cur->m_name == m_currentName)
				cur->onStart(m_currentName, m_currentProperties, characters);
			else
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

bool XmlFactory::parse(std::string str)
{
	try {
		m_validationRun = true;
		parse_memory(str);
		m_validationRun = false;
		parse_memory(str);
	}
	catch(const xmlpp::exception& ex) {
		return false;
	}

	return true;
}

bool XmlFactory::parseFile(std::string fileName)
{
	size_t sz;
	const char *p = (const char *)read_file(&sz, "%s", fileName.c_str());

	if (!p)
		return false;

	std::string str(p);
	free((void *)p);

	return parse(str);
}

void XmlFactory::registerListener(std::string elementName,
		IXmlListener* listener)
{
	listener->setName(elementName);
	m_elementListeners[elementName].push_back(listener);
}

void XmlFactory::on_fatal_error(const Glib::ustring& text)
{
}

void XmlFactory::maybePopListener(const Glib::ustring& name)
{
	if (m_listenerStack.empty())
		return;

	ListenerList_t *p = m_listenerStack.back();

	panic_if (p->empty(),
			"Listener stack list can't be empty");

	if (p->front()->m_name == name)
		m_listenerStack.pop_back();
}

