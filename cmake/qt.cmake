macro(capitalise _string)
	string(SUBSTRING ${${_string}} 0 1 _head)
	string(SUBSTRING ${${_string}} 1 -1 _tail)
	string(TOUPPER ${_head} _head_u)
	string(TOLOWER ${_tail} _tail_l)
	set(${_string} "${_head_u}${_tail_l}")
endmacro()


macro(find_Qt4_or_5 _qt4_full_version)
	set(_parsing_qt4_modules FALSE)
	set(_parsing_qt5_modules FALSE)
	foreach(_currentArg ${ARGN})
		if("${_currentArg}" STREQUAL "MODULES")
			set(_parsing_qt4_modules TRUE)
			set(_parsing_qt5_modules TRUE)
		elseif("${_currentArg}" STREQUAL "QT4_MODULES")
			set(_parsing_qt4_modules TRUE)
			set(_parsing_qt5_modules FALSE)
		elseif("${_currentArg}" STREQUAL "QT5_MODULES")
			set(_parsing_qt4_modules FALSE)
			set(_parsing_qt5_modules TRUE)
		else()
			if(_parsing_qt4_modules)
				string(TOUPPER ${_currentArg} _component_u)
				set(QT_USE_${_component_u} 1)
			endif()
			if(_parsing_qt5_modules)
				set(_component ${_currentArg})
				capitalise(_component)
				list(APPEND QT5_MODULES "${_component}")
			endif()
		endif()
	endforeach()

	if(CMAKE_PREFERRED_QT EQUAL 5 OR NOT CMAKE_PREFERRED_QT)
		foreach(_component ${QT5_MODULES})
			find_package(Qt5${_component})
		endforeach()

		if(Qt5Core_VERSION_MAJOR)
			set(QT_VERSION_MAJOR ${Qt5Core_VERSION_MAJOR})
			set(QT_VERSION_MINOR ${Qt5Core_VERSION_MINOR})
			set(QT_VERSION_PATCH ${Qt5Core_VERSION_PATCH})
			set(QTVERSION ${Qt5Core_VERSION_STRING})
		endif()
	endif()

	if(NOT QT_VERSION_MAJOR)
		find_package(Qt4 ${_qt4_full_version})
	endif()

	if(QTVERSION)
		message(STATUS "Using Qt version ${QTVERSION}")

		if(QT_VERSION_MAJOR EQUAL 4)
			include(${QT_USE_FILE})
		endif()

		if(QTVERSION VERSION_LESS "4.8.2")
			set(QT_DBUS_PREFIX "com.trolltech")
		else()
			set(QT_DBUS_PREFIX "org.qtproject")
		endif()
	else()
		message(STATUS "No Qt found")
	endif()
endmacro()

macro(process_qt_files)
	if(${QT_VERSION_MAJOR} EQUAL 4)
		foreach(DBUS_ADAPTOR ${${PROJECT_NAME}_DBUS_ADAPTORS})
			get_filename_component(DBUS_ADAPTOR_FILENAME ${DBUS_ADAPTOR} NAME)
			configure_file(
				${DBUS_ADAPTOR}
				${CMAKE_CURRENT_BINARY_DIR}/${DBUS_ADAPTOR_FILENAME}
				@ONLY
			)
			get_source_file_property(DBUS_ADAPTOR_INCLUDE ${DBUS_ADAPTOR} INCLUDE)
			get_source_file_property(DBUS_ADAPTOR_PARENT_CLASSNAME ${DBUS_ADAPTOR} PARENT_CLASSNAME)
			get_source_file_property(DBUS_ADAPTOR_BASENAME ${DBUS_ADAPTOR} BASENAME)
			get_source_file_property(DBUS_ADAPTOR_CLASSNAME ${DBUS_ADAPTOR} CLASSNAME)
			if(DBUS_ADAPTOR_BASENAME)
				if(DBUS_ADAPTOR_CLASSNAME)
					qt4_add_dbus_adaptor(${PROJECT_NAME}_DBUS_ADAPTOR_FILES ${CMAKE_CURRENT_BINARY_DIR}/${DBUS_ADAPTOR_FILENAME} ${DBUS_ADAPTOR_INCLUDE} ${DBUS_ADAPTOR_PARENT_CLASSNAME} ${DBUS_ADAPTOR_BASENAME} ${DBUS_ADAPTOR_CLASSNAME})
				else()
					qt4_add_dbus_adaptor(${PROJECT_NAME}_DBUS_ADAPTOR_FILES ${CMAKE_CURRENT_BINARY_DIR}/${DBUS_ADAPTOR_FILENAME} ${DBUS_ADAPTOR_INCLUDE} ${DBUS_ADAPTOR_PARENT_CLASSNAME} ${DBUS_ADAPTOR_BASENAME})
				endif()
			else()
				qt4_add_dbus_adaptor(${PROJECT_NAME}_DBUS_ADAPTOR_FILES ${CMAKE_CURRENT_BINARY_DIR}/${DBUS_ADAPTOR_FILENAME} ${DBUS_ADAPTOR_INCLUDE} ${DBUS_ADAPTOR_PARENT_CLASSNAME})
			endif()
		endforeach()

		foreach(DBUS_INTERFACE ${${PROJECT_NAME}_DBUS_INTERFACES})
			get_filename_component(DBUS_INTERFACE_FILENAME ${DBUS_INTERFACE} NAME)
			configure_file(
				${DBUS_INTERFACE}
				${CMAKE_CURRENT_BINARY_DIR}/${DBUS_INTERFACE_FILENAME}
				@ONLY
			)
			get_source_file_property(DBUS_INTERFACE_BASENAME ${DBUS_INTERFACE} BASENAME)
			get_source_file_property(DBUS_INTERFACE_INCLUDE ${DBUS_INTERFACE} INCLUDE)
			get_source_file_property(DBUS_INTERFACE_CLASSNAME ${DBUS_INTERFACE} CLASSNAME)
			get_source_file_property(DBUS_INTERFACE_NO_NAMESPACE ${DBUS_INTERFACE} NO_NAMESPACE)
			set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/${DBUS_INTERFACE_FILENAME} PROPERTIES
				INCLUDE ${DBUS_INTERFACE_INCLUDE}
				CLASSNAME ${DBUS_INTERFACE_CLASSNAME}
				NO_NAMESPACE ${DBUS_INTERFACE_NO_NAMESPACE}
			)
			qt4_add_dbus_interface(${PROJECT_NAME}_DBUS_INTERFACE_FILES ${CMAKE_CURRENT_BINARY_DIR}/${DBUS_INTERFACE_FILENAME} ${DBUS_INTERFACE_BASENAME})
		endforeach()

		qt4_wrap_cpp(${PROJECT_NAME}_MOC_FILES ${${PROJECT_NAME}_QT_HEADERS})
		qt4_add_resources(${PROJECT_NAME}_RESOURCE_FILES ${${PROJECT_NAME}_RESOURCES})
		if(COMMAND qt4_wrap_ui)
			qt4_wrap_ui(${PROJECT_NAME}_FORM_FILES ${${PROJECT_NAME}_FORMS})
		endif()
		if(COMMAND qt4_create_translation)
			qt4_create_translation(${${PROJECT_NAME}_QM_FILES} ${${PROJECT_NAME}_TRANSLATABLE} ${${PROJECT_NAME}_TRANSLATIONS})
		endif()
	elseif(${QT_VERSION_MAJOR} EQUAL 5)
		foreach(DBUS_ADAPTOR ${${PROJECT_NAME}_DBUS_ADAPTORS})
			get_filename_component(DBUS_ADAPTOR_FILENAME ${DBUS_ADAPTOR} NAME)
			configure_file(
				${DBUS_ADAPTOR}
				${CMAKE_CURRENT_BINARY_DIR}/${DBUS_ADAPTOR_FILENAME}
				@ONLY
			)
			get_source_file_property(DBUS_ADAPTOR_INCLUDE ${DBUS_ADAPTOR} INCLUDE)
			get_source_file_property(DBUS_ADAPTOR_PARENT_CLASSNAME ${DBUS_ADAPTOR} PARENT_CLASSNAME)
			get_source_file_property(DBUS_ADAPTOR_BASENAME ${DBUS_ADAPTOR} BASENAME)
			get_source_file_property(DBUS_ADAPTOR_CLASSNAME ${DBUS_ADAPTOR} CLASSNAME)
			if(DBUS_ADAPTOR_BASENAME)
				if(DBUS_ADAPTOR_CLASSNAME)
					qt5_add_dbus_adaptor(${PROJECT_NAME}_DBUS_ADAPTOR_FILES ${CMAKE_CURRENT_BINARY_DIR}/${DBUS_ADAPTOR_FILENAME} ${DBUS_ADAPTOR_INCLUDE} ${DBUS_ADAPTOR_PARENT_CLASSNAME} ${DBUS_ADAPTOR_BASENAME} ${DBUS_ADAPTOR_CLASSNAME})
				else()
					qt5_add_dbus_adaptor(${PROJECT_NAME}_DBUS_ADAPTOR_FILES ${CMAKE_CURRENT_BINARY_DIR}/${DBUS_ADAPTOR_FILENAME} ${DBUS_ADAPTOR_INCLUDE} ${DBUS_ADAPTOR_PARENT_CLASSNAME} ${DBUS_ADAPTOR_BASENAME})
				endif()
			else()
				qt5_add_dbus_adaptor(${PROJECT_NAME}_DBUS_ADAPTOR_FILES ${CMAKE_CURRENT_BINARY_DIR}/${DBUS_ADAPTOR_FILENAME} ${DBUS_ADAPTOR_INCLUDE} ${DBUS_ADAPTOR_PARENT_CLASSNAME})
			endif()
		endforeach()

		foreach(DBUS_INTERFACE ${${PROJECT_NAME}_DBUS_INTERFACES})
			get_filename_component(DBUS_INTERFACE_FILENAME ${DBUS_INTERFACE} NAME)
			configure_file(
				${DBUS_INTERFACE}
				${CMAKE_CURRENT_BINARY_DIR}/${DBUS_INTERFACE_FILENAME}
				@ONLY
			)
			get_source_file_property(DBUS_INTERFACE_BASENAME ${DBUS_INTERFACE} BASENAME)
			get_source_file_property(DBUS_INTERFACE_INCLUDE ${DBUS_INTERFACE} INCLUDE)
			get_source_file_property(DBUS_INTERFACE_CLASSNAME ${DBUS_INTERFACE} CLASSNAME)
			get_source_file_property(DBUS_INTERFACE_NO_NAMESPACE ${DBUS_INTERFACE} NO_NAMESPACE)
			set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/${DBUS_INTERFACE_FILENAME} PROPERTIES
				INCLUDE ${DBUS_INTERFACE_INCLUDE}
				CLASSNAME ${DBUS_INTERFACE_CLASSNAME}
				NO_NAMESPACE ${DBUS_INTERFACE_NO_NAMESPACE}
			)
			qt5_add_dbus_interface(${PROJECT_NAME}_DBUS_INTERFACE_FILES ${CMAKE_CURRENT_BINARY_DIR}/${DBUS_INTERFACE_FILENAME} ${DBUS_INTERFACE_BASENAME})
		endforeach()

		qt5_wrap_cpp(${PROJECT_NAME}_MOC_FILES ${${PROJECT_NAME}_QT_HEADERS})
		qt5_add_resources(${PROJECT_NAME}_RESOURCE_FILES ${${PROJECT_NAME}_RESOURCES})
		if(COMMAND qt5_wrap_ui)
			qt5_wrap_ui(${PROJECT_NAME}_FORM_FILES ${${PROJECT_NAME}_FORMS})
		endif()
		if(COMMAND qt5_create_translation)
			qt5_create_translation(${${PROJECT_NAME}_QM_FILES} ${${PROJECT_NAME}_TRANSLATABLE} ${${PROJECT_NAME}_TRANSLATIONS})
		endif()
	endif()

	set(${PROJECT_NAME}_GENERATED_FILES
		${${PROJECT_NAME}_MOC_FILES}
		${${PROJECT_NAME}_FORM_FILES}
		${${PROJECT_NAME}_RESOURCE_FILES}
		${${PROJECT_NAME}_QM_FILES}
		${${PROJECT_NAME}_DBUS_INTERFACES}
		${${PROJECT_NAME}_DBUS_ADAPTORS}
	)

	set(${PROJECT_NAME}_ALL_FILES
		${${PROJECT_NAME}_SOURCES}
		${${PROJECT_NAME}_HEADERS}
		${${PROJECT_NAME}_GENERATED_FILES}
	)
endmacro()

macro(process_qt_files_app)
	set(${PROJECT_NAME}_HEADERS
		${${PROJECT_NAME}_CXX_HEADERS}
		${${PROJECT_NAME}_QT_HEADERS}
	)

	set(${PROJECT_NAME}_TRANSLATABLE
		${${PROJECT_NAME}_SOURCES}
		${${PROJECT_NAME}_HEADERS}
		${${PROJECT_NAME}_FORMS}
	)

	process_qt_files()
endmacro()

macro(process_qt_files_lib)
	set(${PROJECT_NAME}_PUBLIC_HEADERS
		${${PROJECT_NAME}_PUBLIC_CXX_HEADERS}
		${${PROJECT_NAME}_PUBLIC_QT_HEADERS}
	)

	set(${PROJECT_NAME}_PRIVATE_HEADERS
		${${PROJECT_NAME}_PRIVATE_CXX_HEADERS}
		${${PROJECT_NAME}_PRIVATE_QT_HEADERS}
	)

	set(${PROJECT_NAME}_CXX_HEADERS
		${${PROJECT_NAME}_PUBLIC_CXX_HEADERS}
		${${PROJECT_NAME}_PRIVATE_CXX_HEADERS}
	)

	set(${PROJECT_NAME}_QT_HEADERS
		${${PROJECT_NAME}_PUBLIC_QT_HEADERS}
		${${PROJECT_NAME}_PRIVATE_QT_HEADERS}
	)

	set(${PROJECT_NAME}_HEADERS
		${${PROJECT_NAME}_MAIN_HEADER}
		${${PROJECT_NAME}_PUBLIC_HEADERS}
		${${PROJECT_NAME}_PRIVATE_HEADERS}
	)

	set(${PROJECT_NAME}_TRANSLATABLE
		${${PROJECT_NAME}_SOURCES}
		${${PROJECT_NAME}_HEADERS}
		${${PROJECT_NAME}_FORMS}
	)

	process_qt_files()
endmacro()

macro(link_target_with_qt _target)
	if(${QT_VERSION_MAJOR} EQUAL 4)
		target_link_libraries(${_target} ${QT_LIBRARIES})
	elseif(${QT_VERSION_MAJOR} EQUAL 5)
		qt5_use_modules(${_target} ${QT5_MODULES})
	endif()
endmacro()
