from extras.plugins import PluginMenu, PluginMenuItem

menu = PluginMenu(
    label="Risk Assessment",
    icon_class="mdi mdi-spider",
    groups=(
        (
            "Threat",
            (
                PluginMenuItem(
                    link="plugins:nb_risk:threatsource_list",
                    link_text="Threat Sources",
                ),
                PluginMenuItem(
                    link="plugins:nb_risk:threatevent_list",
                    link_text="Threat Events",
                ),
            ),
        ),
        (
            "Vulnerability",
            (
                PluginMenuItem(
                    link="plugins:nb_risk:vulnerability_list",
                    link_text="Vulnerabilities",
                ),
            ),
        ),
        (
            "Risk",
            (
                PluginMenuItem(
                    link="plugins:nb_risk:risk_list",
                    link_text="Risks",
                ),
            ),
        ),
    ),
)
