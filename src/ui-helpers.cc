#include <ui-helpers.hh>

#include <utils.hh>

std::string UiHelpers::getFileContents(const std::string& fileName)
{
	size_t sz;
	char *p = (char *)read_file(&sz, "%s", fileName.c_str());
	if (!p)
		return "";

	std::string data(p, sz);
	free(p);

	return data;
}
