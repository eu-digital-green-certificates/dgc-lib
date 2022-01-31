package eu.europa.ec.dgc.gateway.connector.springbootworkaroundforks;

import feign.Feign;
import org.springframework.cloud.openfeign.FeignBuilderCustomizer;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.cloud.openfeign.FeignClientBuilder;
import org.springframework.context.ApplicationContext;

//CHECKSTYLE:OFF
/**
 * Temporary Fork of Spring-Boot's {@link FeignClientBuilder}.
 * Used until https://github.com/spring-cloud/spring-cloud-openfeign/pull/672 will be merged and released.
 * Fore more information see: https://github.com/spring-cloud/spring-cloud-openfeign/issues/671
 *
 * <p>A builder for creating Feign clients without using the {@link FeignClient} annotation.
 *
 * <p>This builder builds the Feign client exactly like it would be created by using the {@link FeignClient} annotation.
 *
 * @author Sven Döring
 * @author Matt King
 * @author Sam Kruglov
 */
public class DgcFeignClientBuilder {

    private final ApplicationContext applicationContext;

    public DgcFeignClientBuilder(final ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    public <T> DgcFeignClientBuilder.Builder<T> forType(final Class<T> type, final String name) {
        return new DgcFeignClientBuilder.Builder<>(this.applicationContext, type, name);
    }

    public <T> DgcFeignClientBuilder.Builder<T> forType(final Class<T> type, final DgcFeignClientFactoryBean clientFactoryBean,
                                                        final String name) {
        return new DgcFeignClientBuilder.Builder<>(this.applicationContext, clientFactoryBean, type, name);
    }

    /**
     * Builder of feign targets.
     *
     * @param <T> type of target
     */
    public static final class Builder<T> {

        private DgcFeignClientFactoryBean feignClientFactoryBean;

        private Builder(final ApplicationContext applicationContext, final Class<T> type, final String name) {
            this(applicationContext, new DgcFeignClientFactoryBean(), type, name);
        }

        private Builder(final ApplicationContext applicationContext, final DgcFeignClientFactoryBean clientFactoryBean,
                        final Class<T> type, final String name) {
            this.feignClientFactoryBean = clientFactoryBean;

            this.feignClientFactoryBean.setApplicationContext(applicationContext);
            this.feignClientFactoryBean.setType(type);
            this.feignClientFactoryBean.setName(DgcFeignClientRegistrar.getName(name));
            this.feignClientFactoryBean.setContextId(DgcFeignClientRegistrar.getName(name));
            this.feignClientFactoryBean.setInheritParentContext(true);
            // preset default values - these values resemble the default values on the
            // FeignClient annotation
            this.url("").path("").decode404(false);
        }

        public DgcFeignClientBuilder.Builder<T> url(final String url) {
            this.feignClientFactoryBean.setUrl(DgcFeignClientRegistrar.getUrl(url));
            return this;
        }

        /**
         * Applies a {@link FeignBuilderCustomizer} to the underlying
         * {@link Feign.Builder}. May be called multiple times.
         *
         * @param customizer applied in the same order as supplied here after applying
         *                   customizers found in the context.
         * @return the {@link DgcFeignClientBuilder.Builder} with the customizer added
         */
        public DgcFeignClientBuilder.Builder<T> customize(final FeignBuilderCustomizer customizer) {
            this.feignClientFactoryBean.addCustomizer(customizer);
            return this;
        }

        public DgcFeignClientBuilder.Builder<T> contextId(final String contextId) {
            this.feignClientFactoryBean.setContextId(contextId);
            return this;
        }

        public DgcFeignClientBuilder.Builder<T> path(final String path) {
            this.feignClientFactoryBean.setPath(DgcFeignClientRegistrar.getPath(path));
            return this;
        }

        public DgcFeignClientBuilder.Builder<T> decode404(final boolean decode404) {
            this.feignClientFactoryBean.setDecode404(decode404);
            return this;
        }

        public DgcFeignClientBuilder.Builder<T> inheritParentContext(final boolean inheritParentContext) {
            this.feignClientFactoryBean.setInheritParentContext(inheritParentContext);
            return this;
        }

        public DgcFeignClientBuilder.Builder<T> fallback(final Class<? extends T> fallback) {
            DgcFeignClientRegistrar.validateFallback(fallback);
            this.feignClientFactoryBean.setFallback(fallback);
            return this;
        }

        /**
         * @return the created Feign client
         */
        public T build() {
            return this.feignClientFactoryBean.getTarget();
        }

    }

}
