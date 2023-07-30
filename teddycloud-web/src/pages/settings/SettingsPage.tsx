import { Breadcrumb } from "antd";
import { useTranslation } from "react-i18next";
import {
  StyledBreadcrumb,
  StyledContent,
  StyledLayout,
  StyledSider,
} from "../../components/StyledComponents";
import { SettingsSubNav } from "../../components/SettingsSubNav";
import { OptionsList, TeddyCloudApi } from "../../api";
import { defaultAPIConfig } from "../../config/defaultApiConfig";
import { useEffect, useState } from "react";

const api = new TeddyCloudApi(defaultAPIConfig());

export const SettingsPage = () => {
  const { t } = useTranslation();
  const [options, setOptions] = useState<OptionsList | undefined>();

  useEffect(() => {
    const fetchOptions = async () => {
      const optionsRequest = (await api.getIndexGet()) as OptionsList;
      if (
        optionsRequest?.options?.length &&
        optionsRequest?.options?.length > 0
      ) {
        setOptions(optionsRequest);
      }
    };

    fetchOptions();
  }, []);

  return (
    <>
      <StyledSider>
        <SettingsSubNav />
      </StyledSider>
      <StyledLayout>
        <StyledBreadcrumb>
          <Breadcrumb.Item>{t("home.navigationTitle")}</Breadcrumb.Item>
          <Breadcrumb.Item>{t("settings.navigationTitle")}</Breadcrumb.Item>
        </StyledBreadcrumb>
        <StyledContent>
          <h1>{t(`settings.title`)}</h1>
          {options?.options?.map((option) => {
            console.log("option", option);
            return (
              <div key={option.iD}>
                <h2>{t("home.option." + option.iD)}</h2>
                <p>{option.shortname}</p>
                <p>{option.type}</p>
              </div>
            );
          })}
        </StyledContent>
      </StyledLayout>
    </>
  );
};
