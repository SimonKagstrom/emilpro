#pragma once

#include <server.hh>

class InstructionModelListener;

namespace emilpro
{
	class NetworkListener : public Server::IListener
	{
	public:
		NetworkListener();

		~NetworkListener();

		virtual void onConnectResult(bool connected, const std::string &status);

		virtual void onXml(const std::string &xml);

	private:
		InstructionModelListener *m_modelListener;
	};
}
