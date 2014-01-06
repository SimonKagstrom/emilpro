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

	private:
		InstructionModelListener *m_modelListener;
	};
}
